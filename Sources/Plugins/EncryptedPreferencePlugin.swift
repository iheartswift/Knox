//
//  EncryptedPreferencePlugin.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-21.
//

import Foundation

public extension Knox {
    
    @objc class EncryptedPreferencePlugin: NSObject, Knox.EncryptedPreferencePluginInterface {

        // MARK: - Properties
        private let store: Knox.KeychainStore
        
        // MARK: - Designated init
        public init(service: String) {
            self.store = Knox.KeychainStore(service: service)
        }

        // MARK: - Get Preference
        public func getPreference(key: String, default: String) async throws -> String {
            guard let data = store.retrieve(forKey: key, biometric: false) else {
                throw Knox.KeychainStore.StoreError.dataNotFound  // Return default if data is not found
            }
            guard let value = String(data: data, encoding: .utf8) else {
                throw Knox.KeychainStore.StoreError.encodingError  // Handle encoding error
            }
            return value
        }

        // MARK: - Put Preference
        public func putPreference(key: String, value: String) async throws {
            guard let data = value.data(using: .utf8) else {
                throw Knox.KeychainStore.StoreError.encodingError  // Handle invalid string encoding
            }
            let success = store.save(data: data, forKey: key, biometric: false)
            if !success {
                throw Knox.KeychainStore.StoreError.keychainError("Failed to save data to Keychain.")
            }
        }

        // MARK: - Has Preference
        public func hasPreference(key: String) async throws -> Bool {
            let data = store.retrieve(forKey: key, biometric: false)
            return data != nil  // Return true if data exists, false otherwise
        }

        // MARK: - Remove Preference
        public func removePreference(key: String) async throws {
            let success = store.delete(forKey: key)
            if !success {
                throw Knox.KeychainStore.StoreError.keychainError("Failed to delete item from Keychain.")
            }
        }
    }
}
