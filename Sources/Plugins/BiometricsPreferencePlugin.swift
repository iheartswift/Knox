//
//  BiometricsPreferencePlugin.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-21.
//

import Foundation

// NOTE: - Operations requiring biometric authentication must run on the main thread to properly trigger the UI.

public extension Knox {
    
    @MainActor @objc class BiometricsPreferencePlugin: NSObject, Knox.EncryptedPreferencePluginInterface {

        // MARK: - Properties
        private let keychainStore = Knox.KeychainStore(service: "com.cibc.biometrics.preferences")

        // MARK: - Get Preference
        public func getPreference(key: String, default: String) async throws -> String {
            guard let data = keychainStore.retrieve(forKey: key, biometric: true) else {
                throw Knox.KeychainStore.StoreError.dataNotFound  // Throw if data is not found
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
            let success = keychainStore.save(data: data, forKey: key, biometric: true)
            if !success {
                throw Knox.KeychainStore.StoreError.keychainError("Failed to save data to Keychain with biometric authentication.")
            }
        }

        // MARK: - Has Preference
        public func hasPreference(key: String) async throws -> Bool {
            let data = keychainStore.retrieve(forKey: key, biometric: true)
            return data != nil  // Return true if data exists, false otherwise
        }

        // MARK: - Remove Preference
        public func removePreference(key: String) async throws {
            let success = keychainStore.delete(forKey: key)
            if !success {
                throw Knox.KeychainStore.StoreError.keychainError("Failed to delete item from Keychain.")
            }
        }
    }
}
