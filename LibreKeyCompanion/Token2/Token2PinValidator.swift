import Foundation

/// Client-side OTP-PIN policy, mirroring the reference `validate_otp_pin` (and the
/// Android `Token2PinValidator.kt`). The device enforces its own policy too, but
/// validating here gives the user a clear message before a bad-format PIN is sent.
enum Token2PinValidator {

    /// Returns nil if acceptable, else a human-readable reason.
    static func validate(_ pin: String) -> String? {
        let bytes = Array(pin.utf8)
        if bytes.isEmpty { return "PIN must not be empty" }
        if bytes.count > 255 { return "PIN is too long" }
        let allDigits = pin.allSatisfy { $0.isNumber && $0.isASCII }
        return allDigits ? validateNumeric(pin) : validateAlphanumeric(pin)
    }

    private static func validateNumeric(_ pin: String) -> String? {
        if pin.count < 6 { return "Numeric PIN must be at least 6 digits" }
        let chars = Array(pin)
        if chars.allSatisfy({ $0 == chars[0] }) { return "Numeric PIN must not be all the same digit" }
        let asc = zip(chars, chars.dropFirst()).allSatisfy { Int(String($1))! == Int(String($0))! + 1 }
        let desc = zip(chars, chars.dropFirst()).allSatisfy { Int(String($0))! == Int(String($1))! + 1 }
        if asc || desc { return "Numeric PIN must not be a simple ascending/descending sequence" }
        if pin == String(pin.reversed()) { return "Numeric PIN must not be a palindrome" }
        for d in "0123456789" where chars.filter({ $0 == d }).count > 3 {
            return "Numeric PIN repeats a single digit too many times"
        }
        return nil
    }

    private static func validateAlphanumeric(_ pin: String) -> String? {
        if pin.count < 10 { return "Alphanumeric PIN must be at least 10 characters" }
        var classes = 0
        if pin.contains(where: { $0.isUppercase }) { classes += 1 }
        if pin.contains(where: { $0.isLowercase }) { classes += 1 }
        if pin.contains(where: { $0.isNumber }) { classes += 1 }
        if pin.contains(where: { !$0.isLetter && !$0.isNumber }) { classes += 1 }
        if classes < 2 { return "Alphanumeric PIN must mix at least two character types" }
        return nil
    }
}
