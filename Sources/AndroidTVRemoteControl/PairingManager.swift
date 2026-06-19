//
//  PairingManager.swift
//  
//
//  Created by Roman Odyshew on 15.10.2023.
//

import Foundation
import Network
import CryptoKit

public class PairingManager {
    private let stateQueue = DispatchQueue(label: "pairing.state")
    private let connectQueue = DispatchQueue(label: "pairing.connect")
    
    private var pairingResponse = PairingNetwork.PairingResponse()
    private var optionResponse = PairingNetwork.OptionResponse()
    private var configResponse = PairingNetwork.ConfigurationResponse()

    /// Accumulates raw TCP bytes until a complete length-prefixed message is available. TCP has no
    /// message boundaries, so the varint length and the body can arrive coalesced in one read or
    /// split across several — see `nextCompleteMessage`.
    private var buffer = Data()

    private var connection: NWConnection?
    private var cryptoManager: CryptoManager
    private let tlsManager: TLSManager
    
    private var clientName = "client"
    private var serviceName = "service"
    private var code: String = ""
    
    public var logger: Logger?
    private let logPrefix = "Pairing: "
    
    public var stateChanged: ((PairingState)->())?
    
    private var pairingState: PairingState = .idle {
        didSet {
            let state = pairingState
            
            stateQueue.async {
                switch state {
                case .idle:
                    self.logger?.infoLog(self.logPrefix + "idle")
                case .extractTLSparams:
                    self.logger?.infoLog(self.logPrefix + "extract TLS parameters")
                case .connectionSetUp:
                    self.logger?.infoLog(self.logPrefix + "connection set up")
                case .connectionPrepairing:
                    self.logger?.infoLog(self.logPrefix + "connection prepairing")
                case .connected:
                    self.logger?.infoLog(self.logPrefix + "connected")
                case .pairingRequestSent:
                    self.logger?.infoLog(self.logPrefix + "pairing request has been sent")
                case .pairingResponseSuccess:
                    self.logger?.infoLog(self.logPrefix + "pairing sesponse success")
                case .optionRequestSent:
                    self.logger?.infoLog(self.logPrefix + "option request sent")
                case .optionResponseSuccess:
                    self.logger?.infoLog(self.logPrefix + "option response success")
                case .confirmationRequestSent:
                    self.logger?.infoLog(self.logPrefix + "confirmation request has been sent")
                case .confirmationResponseSuccess:
                    self.logger?.infoLog(self.logPrefix + "confirmation response success")
                case .waitingCode:
                    self.logger?.infoLog(self.logPrefix + "waiting code")
                case .secretSent:
                    self.logger?.infoLog(self.logPrefix + "secret has been sent")
                case .successPaired:
                    self.logger?.infoLog(self.logPrefix + "success paired")
                case .error(let error):
                    self.logger?.errorLog(self.logPrefix + error.localizedDescription)
                }
                
                self.stateChanged?(state)
            }
        }
    }
    
    public init(_ tlsManager: TLSManager, _ cryptoManager: CryptoManager, _ logger: Logger? = nil) {
        self.tlsManager = tlsManager
        self.cryptoManager = cryptoManager
        self.logger = logger
    }
    
    public func connect(_ host: String, _ clientName: String, _ serviceName: String, port: UInt16 = 6467, timeout: Int = 60) {
        if host.isEmpty {
            logger?.errorLog(logPrefix + "host shouldn't be empty!")
        }

        self.clientName = clientName
        self.serviceName = serviceName

        pairingState = .extractTLSparams

        let tlsParams: NWParameters

        switch tlsManager.getNWParams(connectQueue, timeout: timeout) {
        case .Result(let params):
            tlsParams = params
        case .Error(let error):
            pairingState = .error(error)
            return
        }

        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port),
            using: tlsParams)

        connection?.stateUpdateHandler = handleConnectionState
        logger?.infoLog(logPrefix + "connecting " + host + ":\(port)")
        connection?.start(queue: connectQueue)
    }
    
    public func disconnect() {
        logger?.infoLog(logPrefix + "disconnect")
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
        buffer = Data()
    }
    
    public func sendSecret(_ code: String) {
        // Set the code for secret transmission
        logger?.debugLog("code: " + code)
        self.code = code
        let secret: [UInt8]
        switch cryptoManager.getEncodedCert(code) {
        case .Result(let data):
            secret = data
        case .Error(let error):
            pairingState = .error(error)
            disconnect()
            return
        }
        
        send(PairingNetwork.SecretRequest(encodedCert: secret))
        pairingState = .secretSent
        
        receive()
    }
    
    private func handleConnectionState(_ state: NWConnection.State) {
        switch state {
        case .setup:
            pairingState = .connectionSetUp
        case .waiting(let error):
            pairingState = .error(.connectionWaitingError(error))
            disconnect()
        case .preparing:
            pairingState = .connectionPrepairing
        case .ready:
            pairingState = .connected
            buffer = Data()

            pairingResponse = PairingNetwork.PairingResponse()
            logger?.debugLog(logPrefix + "Sending pairing request")
            send(PairingNetwork.PairingRequest(clientName: clientName, serviceName: serviceName))
            pairingState = .pairingRequestSent
            
            receive()
        case .failed(let error):
            pairingState = .error(.connectionFailed(error))
            disconnect()
        case .cancelled:
            pairingState = .error(.connectionCanceled)
            disconnect()
        default:
            break
        }
    }
    
    private func receive() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] (data, context, isComplete, error) in
            guard let `self` = self else { return }

            if let error = error {
                self.pairingState = .error(.receiveDataError(error))
                return
            }

            guard let data = data, !data.isEmpty, isComplete == false else {
                self.logger?.infoLog(self.logPrefix + "Empty or completion data received")
                self.receive()
                return
            }

            self.logger?.debugLog(self.logPrefix + "recived: \(Array(data))")

            // Accumulate, then drain every COMPLETE length-prefixed message. The old code assumed
            // read #1 == varint length and read #2 == body; TCP gives no such guarantee, so a
            // coalesced or split read corrupted `.data` and produced spurious option/configuration
            // NotSuccess before the PIN ever showed.
            self.buffer.append(data)
            self.processBuffer()
        }
    }

    /// Drains every complete message currently buffered, advancing the pairing state machine. Calls
    /// `receive()` again only while still expecting more network data (not after waitingCode/error).
    private func processBuffer() {
        while let message = nextCompleteMessage() {
            guard handleMessage(message.body, message.full) else { return }
        }
        receive()
    }

    /// Extracts the next complete `<varint length><body>` message from `buffer`, consuming it.
    /// Returns nil while the length prefix or the body is still incomplete.
    private func nextCompleteMessage() -> (body: Data, full: Data)? {
        let bytes = [UInt8](buffer)
        guard !bytes.isEmpty, let decoded = Decoder.decodeVarint(bytes) else { return nil }
        let prefix = decoded.bytesCount
        // Reject a partial varint (continuation bit still set on the last decoded byte).
        guard prefix <= bytes.count, (bytes[prefix - 1] & 0x80) == 0 else { return nil }
        let total = prefix + Int(decoded.value)
        guard bytes.count >= total else { return nil }
        let full = Data(bytes[0..<total])
        let body = Data(bytes[prefix..<total])
        buffer = Data(bytes[total...])
        return (body, full)
    }

    /// Processes one complete pairing message for the current state. `body` is the message without
    /// its length prefix (what Pairing/Option/Configuration responses expect); `full` is the whole
    /// length-prefixed message (what SecretResponse and the error payloads expect). Returns true to
    /// keep draining the buffer, false on a terminal or await state.
    private func handleMessage(_ body: Data, _ full: Data) -> Bool {
        switch pairingState {
        case .pairingRequestSent: return handlePairingResponse(body, full)
        case .optionRequestSent: return handleOptionResponse(body, full)
        case .confirmationRequestSent: return handleConfigurationResponse(body, full)
        case .secretSent: return handleSecretResponse(full)
        default: return false
        }
    }

    private func handlePairingResponse(_ body: Data, _ full: Data) -> Bool {
        pairingResponse.length = Data()
        pairingResponse.data = body
        guard pairingResponse.isSuccess else {
            pairingState = .error(.pairingNotSuccess(full))
            return false
        }
        pairingState = .pairingResponseSuccess
        optionResponse = PairingNetwork.OptionResponse()
        logger?.debugLog(logPrefix + "Sending option request")
        send(PairingNetwork.OptionRequest())
        pairingState = .optionRequestSent
        return true
    }

    private func handleOptionResponse(_ body: Data, _ full: Data) -> Bool {
        optionResponse.length = Data()
        optionResponse.data = body
        guard optionResponse.isSuccess else {
            pairingState = .error(.optionNotSuccess(full))
            return false
        }
        pairingState = .optionResponseSuccess
        configResponse = PairingNetwork.ConfigurationResponse()
        logger?.debugLog(logPrefix + "Sending configuration request")
        send(PairingNetwork.ConfigurationRequest())
        pairingState = .confirmationRequestSent
        return true
    }

    private func handleConfigurationResponse(_ body: Data, _ full: Data) -> Bool {
        configResponse.length = Data()
        configResponse.data = body
        guard configResponse.isSuccess else {
            pairingState = .error(.configurationNotSuccess(full))
            return false
        }
        pairingState = .confirmationResponseSuccess
        pairingState = .waitingCode
        return false
    }

    private func handleSecretResponse(_ full: Data) -> Bool {
        let secretResponse = PairingNetwork.SecretResponse(data: full, code: code)
        pairingState = secretResponse.isSuccess ? .successPaired : .error(.secretNotSuccess(full))
        disconnect()
        return false
    }
    
    private func send(_ request: RequestDataProtocol) {
        send(Data(Encoder.encodeVarint(UInt(request.data.count))), request.data)
    }
    
    private func send(_ data: Data, _ nextData: Data? = nil) {
        logger?.debugLog(logPrefix + "Sending data: \(Array(data))")
        connection?.send(content: data, completion: .contentProcessed({ [weak self] (error) in
            guard let `self` = self else {
                return
            }
            
            if let error = error {
                self.pairingState = .error(.sendDataError(error))
                self.disconnect()
                return
            }
            
            self.logger?.debugLog(self.logPrefix + "Success sent")
            if let nextMessage = nextData {
                self.send(nextMessage)
            }
        }))
    }
}

extension PairingManager {
   public enum PairingState {
        case idle
        case extractTLSparams
        case connectionSetUp
        case connectionPrepairing
        case connected
        case pairingRequestSent
        case pairingResponseSuccess
        case optionRequestSent
        case optionResponseSuccess
        case confirmationRequestSent
        case confirmationResponseSuccess
        case waitingCode
        case secretSent
        case successPaired
        case error(AndroidTVRemoteControlError)
    }
}
