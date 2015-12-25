Pod::Spec.new do |s|
  s.name         = 'GSCrypto'
  s.version      = '3.0.1'
  s.author       = 'GyazSquare'
  s.license      = { :type => 'MIT' }
  s.homepage     = 'https://github.com/GyazSquare/GSCrypto'
  s.source       = { :git => 'https://github.com/GyazSquare/GSCrypto.git', :tag => 'v3.0.1' }
  s.summary      = 'A simple digest library for iOS, OS X, watchOS and tvOS.'
  s.ios.deployment_target = '5.0'
  s.osx.deployment_target = '10.6'
  s.tvos.deployment_target = '9.0'
  s.watchos.deployment_target = '2.0'
  s.requires_arc = true
  s.source_files = 'GSCrypto/*.{h,m}'
end
