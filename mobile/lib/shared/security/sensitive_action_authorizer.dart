import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:local_auth/local_auth.dart';

/// Coarse outcomes safe to use for control flow without retaining OS details.
enum DeviceAuthResult { success, cancelled, unavailable, lockedOut, failed }

abstract interface class SensitiveActionAuthorizer {
  Future<DeviceAuthResult> authorizeIdentityAction();
}

class LocalSensitiveActionAuthorizer implements SensitiveActionAuthorizer {
  LocalSensitiveActionAuthorizer([LocalAuthentication? authentication])
    : _authentication = authentication ?? LocalAuthentication();

  final LocalAuthentication _authentication;

  @override
  Future<DeviceAuthResult> authorizeIdentityAction() async {
    try {
      final supported = await _authentication.isDeviceSupported();
      if (!supported) return DeviceAuthResult.unavailable;
      final authenticated = await _authentication.authenticate(
        localizedReason: 'Confirm sending your Buzz identity to desktop',
        biometricOnly: false,
        sensitiveTransaction: true,
        persistAcrossBackgrounding: false,
      );
      return authenticated ? DeviceAuthResult.success : DeviceAuthResult.failed;
    } on LocalAuthException catch (error) {
      return switch (error.code) {
        LocalAuthExceptionCode.userCanceled ||
        LocalAuthExceptionCode.systemCanceled ||
        LocalAuthExceptionCode.timeout => DeviceAuthResult.cancelled,
        LocalAuthExceptionCode.temporaryLockout ||
        LocalAuthExceptionCode.biometricLockout => DeviceAuthResult.lockedOut,
        LocalAuthExceptionCode.noCredentialsSet ||
        LocalAuthExceptionCode.noBiometricsEnrolled ||
        LocalAuthExceptionCode.noBiometricHardware ||
        LocalAuthExceptionCode.biometricHardwareTemporarilyUnavailable ||
        LocalAuthExceptionCode.uiUnavailable => DeviceAuthResult.unavailable,
        _ => DeviceAuthResult.failed,
      };
    } catch (_) {
      return DeviceAuthResult.failed;
    }
  }
}

final sensitiveActionAuthorizerProvider = Provider<SensitiveActionAuthorizer>((
  ref,
) {
  return LocalSensitiveActionAuthorizer();
});

class SensitiveActionAuthorizationSession {
  SensitiveActionAuthorizationSession(this._authorizer);

  final SensitiveActionAuthorizer _authorizer;
  Future<DeviceAuthResult>? _authorizationInFlight;

  Future<DeviceAuthResult> authorize() async {
    final inFlight = _authorizationInFlight;
    if (inFlight != null) return inFlight;

    final authorization = _authorizer.authorizeIdentityAction();
    _authorizationInFlight = authorization;
    try {
      final result = await authorization;
      return result;
    } finally {
      if (identical(_authorizationInFlight, authorization)) {
        _authorizationInFlight = null;
      }
    }
  }
}

final sensitiveActionAuthorizationSessionProvider =
    Provider<SensitiveActionAuthorizationSession>((ref) {
      return SensitiveActionAuthorizationSession(
        ref.watch(sensitiveActionAuthorizerProvider),
      );
    });
