//
//  StorageType.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-21.
//

import Foundation

public extension Knox {
    
    enum StorageType: String, Codable, CaseIterable, Identifiable {
        case encryptedPreferences = "Encrypted"
        case biometricsPreference = "Biometric"
        case secureEnclavePreference = "SecureE"
        case biometricsSecureEnclavePreference = "Bio/SecureE"

        public var id: String { self.rawValue }
    }
}
