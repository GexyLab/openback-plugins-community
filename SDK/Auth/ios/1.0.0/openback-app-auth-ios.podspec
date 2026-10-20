Pod::Spec.new do |s|
  s.name             = 'openback-app-auth-ios'
  s.module_name      = 'OpenBackAppAuth'
  s.version          = '1.0.0'
  s.summary          = 'Swift client of OpenBack App authenticator user pools.'
  s.description      = <<-DESC
    Sign-up, password, email code, guest and two-step sign-in, the pool's hosted sign-in page (OpenID Connect + PKCE)
    with ASWebAuthenticationSession, Keychain token storage, single-flight token renewal and a SwiftUI model.
  DESC
  s.homepage         = 'https://github.com/GexyLab/openback-plugins-community/tree/production/SDK/Auth/ios/1.0.0'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'GexyLab' => 'https://github.com/GexyLab' }
  s.source           = { :git => 'https://github.com/GexyLab/openback-plugins-community.git', :tag => 'openback-app-auth-ios-1.0.0' }

  s.swift_versions   = ['5.9', '5.10']
  s.ios.deployment_target     = '15.0'
  s.osx.deployment_target     = '12.0'
  s.tvos.deployment_target    = '15.0'
  s.watchos.deployment_target = '8.0'

  # Paths are relative to this podspec's directory (pod lib lint, :path installs, a dedicated repository).
  s.source_files     = 'Sources/OpenBackAppAuth/**/*.swift'
  s.frameworks       = 'Foundation', 'Security', 'CryptoKit'
  s.ios.frameworks   = 'AuthenticationServices', 'UIKit'
  s.osx.frameworks   = 'AuthenticationServices', 'AppKit'
end
