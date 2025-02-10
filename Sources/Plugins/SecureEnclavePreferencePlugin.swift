//
//  SecureEnclavePreferencePlugin.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-21.
//

import Foundation

public extension Knox {
    
    @objc class SecureEnclavePreferencePlugin: NSObject, Knox.EncryptedPreferencePluginInterface {

        // MARK: - Properties
        private let store: Knox.SecureEnclaveStore
        
        // MARK: - Designated init
        public init(service: String) {
            self.store = Knox.SecureEnclaveStore(service: service)
        }

        // MARK: - Get Preference
        public func getPreference(key: String, default: String) async throws -> String {
            do {
                let data = try store.retrieve(forKey: key, biometric: false, reason: "Authenticate to access your secure data")
                guard let value = String(data: data, encoding: .utf8) else {
                    throw Knox.SecureEnclaveStore.StoreError.dataNotFound
                }
                return value
            } catch {
                throw Knox.SecureEnclaveStore.StoreError.keyRetrievalFailed("Failed to fetch preference: \(error.localizedDescription)")
            }
        }

        // MARK: - Put Preference
        public func putPreference(key: String, value: String) async throws {
            guard let data = value.data(using: .utf8) else {
                throw Knox.SecureEnclaveStore.StoreError.encodingFailed("Failed to create data from value.")
            }
            do {
                try store.save(data: data, forKey: key, biometric: false, reason: "Authenticate to access your secure data")
            } catch {
                throw Knox.SecureEnclaveStore.StoreError.keyRetrievalFailed("Failed to save preference: \(error.localizedDescription)")
            }
        }

        // MARK: - Has Preference
        public func hasPreference(key: String) async throws -> Bool {
            return store.keyExists(forKey: key)
        }

        // MARK: - Remove Preference
        public func removePreference(key: String) async throws {
            let success = store.delete(forKey: key)
            if !success {
                throw Knox.SecureEnclaveStore.StoreError.keyDeletionFailed("Failed to delete value for key: \(key)")
            }
        }
    }
}
