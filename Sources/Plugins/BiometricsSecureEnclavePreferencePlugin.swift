//
//  BiometricsSecureEnclavePreferencePlugin.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-21.
//

import Foundation

// NOTE: - Operations requiring biometric authentication must run on the main thread to properly trigger the UI.

public extension Knox {
    
    @MainActor @objc class BiometricsSecureEnclavePreferencePlugin: NSObject, Knox.EncryptedPreferencePluginInterface {

        // MARK: - Properties
        private let store: Knox.SecureEnclaveStore
        
        // MARK: - Designated init
        init(service: String) {
            self.store = Knox.SecureEnclaveStore(service: service)
        }

        // MARK: - Get Preference
        public func getPreference(key: String, default defaultValue: String) async throws -> String {
            do {
                let data = try store.retrieve(forKey: key, biometric: true, reason: "Authenticate to access your secure data")

                // Attempt to decode the retrieved data into a string
                guard let value = String(data: data, encoding: .utf8) else {
                    throw Knox.SecureEnclaveStore.StoreError.encodingFailed("Failed to decode preference as UTF-8 string.")
                }
                return value
            } catch Knox.SecureEnclaveStore.StoreError.dataNotFound {
                // Return the default value if the key doesn't exist
                return defaultValue
            } // Other StoreError cases will propagate naturally
        }

        // MARK: - Put Preference
        public func putPreference(key: String, value: String) async throws {
            guard let data = value.data(using: .utf8) else {
                throw Knox.SecureEnclaveStore.StoreError.encodingFailed("Failed to encode preference as UTF-8 data.")
            }
            try store.save(data: data, forKey: key, biometric: true, reason: "Authenticate to access your secure data")
        }

        // MARK: - Has Preference
        public func hasPreference(key: String) async throws -> Bool {
            return store.keyExists(forKey: key)
        }

        // MARK: - Remove Preference
        public func removePreference(key: String) async throws {
            let success = store.delete(forKey: key)
            if !success {
                throw Knox.SecureEnclaveStore.StoreError.keyDeletionFailed("Failed to delete preference.")
            }
        }
    }
}
