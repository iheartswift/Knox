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
        public let key: String
        public let storageType: Knox.StorageType
        public var isRevealed: Bool = false
        
        public init(key: String, storageType: Knox.StorageType) {
            self.key = key
            self.storageType = storageType
        }
    }
}
