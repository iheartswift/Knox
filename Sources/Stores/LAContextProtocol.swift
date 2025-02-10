//
//  LAContextProtocol.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-27.
//

import LocalAuthentication

public extension Knox {
    
    /// Protocol for LAContext to enable mocking.
    protocol LAContextProtocol {
        var localizedFallbackTitle: String? { get set }
        func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
        func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void)
    }
    
    /// Default implementation of LAContextProtocol using LAContext.
    final class LAContextWrapper: Knox.LAContextProtocol {
        private let context = LAContext()
        
        public init() { }
        
        public var localizedFallbackTitle: String? {
           get { context.localizedFallbackTitle }
           set { context.localizedFallbackTitle = newValue }
        }

        public func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
            return context.canEvaluatePolicy(policy, error: error)
        }

        public func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply:@escaping (Bool, Error?) -> Void) {
            context.evaluatePolicy(policy, localizedReason: localizedReason, reply: reply)
        }
    }
}
