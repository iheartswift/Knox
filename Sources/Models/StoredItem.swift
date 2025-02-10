//
//  StoredItem.swift
//  EncryptedPrefs
//
//  Created by Adam Dahan on 2024-10-21.
//

import Foundation

public extension Knox {
    
    struct StoredItem: Identifiable, Codable {
        public var id = UUID()
        let key: String
        let storageType: StorageType
        var isRevealed: Bool = false
    }
}
