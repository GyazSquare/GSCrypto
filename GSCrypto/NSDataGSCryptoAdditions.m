//
//  NSDataGSCryptoAdditions.m
//  GSCrypto
//

@import Foundation;

#import "NSDataGSCryptoAdditions.h"

NSString * const GSCryptoErrorDomain = @"GSCryptoErrorDomain";

static NSError * __GSErrorWithCryptoStatus(CCCryptorStatus status) {
    NSString *localizedDescription;
    switch (status) {
        case kCCSuccess:
            return nil;
        case kCCParamError:
            localizedDescription = @"Illegal parameter value.";
            break;
        case kCCBufferTooSmall:
            localizedDescription = @"Insufficent buffer provided for specified operation.";
            break;
        case kCCMemoryFailure:
            localizedDescription = @"Memory allocation failure.";
            break;
        case kCCAlignmentError:
            localizedDescription = @"Input size was not aligned properly.";
            break;
        case kCCDecodeError:
            localizedDescription = @"Input data did not decode or decrypt properly.";
            break;
        case kCCUnimplemented:
            localizedDescription = @"Function not implemented for the current algorithm.";
            break;
        default:
            break;
    }
    NSDictionary *userInfo = localizedDescription ? @{NSLocalizedDescriptionKey: localizedDescription} : nil;
    return [NSError errorWithDomain:GSCryptoErrorDomain code:status userInfo:userInfo];
}

@implementation NSData (GSHMACDigest)

- (NSData *)gs_HMACDigestUsingAlgorithm:(GSHMACAlgorithm)algorithm key:(NSData *)key {
    size_t length;
    switch (algorithm) {
        case GSHMACAlgorithmSHA1:
            length = CC_SHA1_DIGEST_LENGTH;
            break;
        case GSHMACAlgorithmMD5:
            length = CC_MD5_DIGEST_LENGTH;
            break;
        case GSHMACAlgorithmSHA256:
            length = CC_SHA256_DIGEST_LENGTH;
            break;
        case GSHMACAlgorithmSHA384:
            length = CC_SHA384_DIGEST_LENGTH;
            break;
        case GSHMACAlgorithmSHA512:
            length = CC_SHA512_DIGEST_LENGTH;
            break;
        case GSHMACAlgorithmSHA224:
            length = CC_SHA224_DIGEST_LENGTH;
            break;
    }
    unsigned char data[length];
    CCHmac(algorithm, key.bytes, key.length, self.bytes, self.length, data);
    return [NSData dataWithBytes:data length:length];
}

@end

@implementation NSData (GSCrypto)

- (NSData *)gs_encryptedDataUsingAlgorithm:(GSCryptoAlgorithm)algorithm options:(GSCryptoOptions)options key:(NSData *)key initializationVector:(NSData *)initializationVector error:(NSError **)error {
    return [self gs_cryptedDataWithOperation:kCCEncrypt usingAlgorithm:algorithm options:options key:key initializationVector:initializationVector error:error];
}

- (NSData *)gs_decryptedDataUsingAlgorithm:(GSCryptoAlgorithm)algorithm options:(GSCryptoOptions)options key:(NSData *)key initializationVector:(NSData *)initializationVector error:(NSError **)error {
    return [self gs_cryptedDataWithOperation:kCCDecrypt usingAlgorithm:algorithm options:options key:key initializationVector:initializationVector error:error];
}

#pragma mark - Class extensions

- (NSData *)gs_cryptedDataWithOperation:(CCOperation)operation usingAlgorithm:(GSCryptoAlgorithm)algorithm options:(GSCryptoOptions)options key:(NSData *)key initializationVector:(NSData *)initializationVector error:(NSError **)error {
    __block NSData *cryptedData = nil;
    __block CCCryptorRef cryptor = NULL;
    __block CCCryptorStatus status = kCCSuccess;
    NSData * (^finallyBlock)(void) = ^ NSData * {
        if (cryptor) {
            CCCryptorRelease(cryptor);
        }
        if (status != kCCSuccess) {
            if (error) {
                *error = __GSErrorWithCryptoStatus(status);
            }
            return nil;
        }
        return cryptedData;
    };
    status = CCCryptorCreate(operation, algorithm, options, key.bytes, key.length, initializationVector.bytes, &cryptor);
    if (status != kCCSuccess) {
        return finallyBlock();
    }
    const void *dataIn = self.bytes;
    size_t dataInLength = self.length;
    size_t dataOutLength = CCCryptorGetOutputLength(cryptor, self.length, true);
    NSMutableData *data = [NSMutableData dataWithLength:dataOutLength];
    void *dataOut = data.mutableBytes;
    size_t dataOutAvailable = dataOutLength;
    size_t dataOutMoved;
    status = CCCryptorUpdate(cryptor, dataIn, dataInLength, dataOut, dataOutAvailable, &dataOutMoved);
    if (status != kCCSuccess) {
        return finallyBlock();
    }
    dataOutLength = dataOutMoved;
    dataOut += dataOutMoved;
    dataOutAvailable -= dataOutMoved;
    status = CCCryptorFinal(cryptor, dataOut, dataOutAvailable, &dataOutMoved);
    if (status != kCCSuccess) {
        return finallyBlock();
    }
    dataOutLength += dataOutMoved;
    data.length = dataOutLength;
    cryptedData = data;
    return finallyBlock();
}

@end
