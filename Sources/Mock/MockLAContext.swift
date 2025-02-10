//
//  MockLAContext.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-27.
//

import LocalAuthentication

public extension Knox {
    
    class MockLAContext: Knox.LAContextProtocol {
        public var canEvaluatePolicyReturnValue: Bool = false
        public var evaluatePolicyReply: (success: Bool, error: Error?) = (false, nil)

        public func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
            return canEvaluatePolicyReturnValue
        }

        public func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void) {
            reply(evaluatePolicyReply.success, evaluatePolicyReply.error)
        }
        
        public var localizedFallbackTitle: String?
        public var evaluatedPolicyDomainState: Data? {
            return nil
        }
    }
}
