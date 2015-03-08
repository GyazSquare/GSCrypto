//
//  NSDataGSCryptoAdditions.h
//  GSCrypto
//

@import Foundation.NSData;

#include <CommonCrypto/CommonCrypto.h>

typedef NS_ENUM(NSUInteger, GSHMACAlgorithm) {
    GSHMACAlgorithmSHA1 = kCCHmacAlgSHA1,
    GSHMACAlgorithmMD5 = kCCHmacAlgMD5,
    GSHMACAlgorithmSHA256 = kCCHmacAlgSHA256,
    GSHMACAlgorithmSHA384 = kCCHmacAlgSHA384,
    GSHMACAlgorithmSHA512 = kCCHmacAlgSHA512,
    GSHMACAlgorithmSHA224 = kCCHmacAlgSHA224
};

@interface NSData (GSHMACDigest)

- (NSData *)gs_HMACDigestUsingAlgorithm:(GSHMACAlgorithm)algorithm key:(NSData *)key;

@end

typedef NS_ENUM(NSInteger, GSCryptoAlgorithm) {
    GSCryptoAlgorithmAES = kCCAlgorithmAES,
    GSCryptoAlgorithmDES = kCCAlgorithmDES,
    GSCryptoAlgorithm3DES = kCCAlgorithm3DES,
    GSCryptoAlgorithmCAST = kCCAlgorithmCAST,
    GSCryptoAlgorithmRC4 = kCCAlgorithmRC4,
    GSCryptoAlgorithmRC2 = kCCAlgorithmRC2,
    GSCryptoAlgorithmBlowfish = kCCAlgorithmBlowfish
};

typedef NS_OPTIONS(NSUInteger, GSCryptoOptions) {
    GSCryptoOptionPKCS7Padding = kCCOptionPKCS7Padding,
    GSCryptoOptionECBMode = kCCOptionECBMode
};

@interface NSData (GSCrypto)

- (NSData *)gs_encryptedDataUsingAlgorithm:(GSCryptoAlgorithm)algorithm options:(GSCryptoOptions)options key:(NSData *)key initializationVector:(NSData *)initializationVector error:(NSError **)error;
- (NSData *)gs_decryptedDataUsingAlgorithm:(GSCryptoAlgorithm)algorithm options:(GSCryptoOptions)options key:(NSData *)key initializationVector:(NSData *)initializationVector error:(NSError **)error;

@end

FOUNDATION_EXPORT NSString * const GSCryptoErrorDomain;

typedef NS_ENUM(NSInteger, GSCryptoError) {
    GSCryptoErrorSuccess = kCCSuccess,
    GSCryptoErrorParamError = kCCParamError,
    GSCryptoErrorBufferTooSmall = kCCBufferTooSmall,
    GSCryptoErrorMemoryFailure = kCCMemoryFailure,
    GSCryptoErrorAlignmentError = kCCAlignmentError,
    GSCryptoErrorDecodeError = kCCDecodeError,
    GSCryptoErrorUnimplemented = kCCUnimplemented,
    GSCryptoErrorOverflow = kCCOverflow,
    GSCryptoErrorRNGFailure = kCCRNGFailure
};
