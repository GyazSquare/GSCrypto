Pod::Spec.new do |s|
  s.name         = 'GSCrypto'
  s.version      = '1.3.1'
  s.author       = 'GyazSquare'
  s.license      = { :type => 'MIT' }
  s.homepage     = 'https://github.com/GyazSquare/GSCrypto'
  s.source       = { :git => 'https://github.com/GyazSquare/GSCrypto.git', :tag => '1.3.1' }
  s.summary      = 'A simple digest library for iOS, OS X and watchOS.'
  s.ios.deployment_target = '5.0'
  s.osx.deployment_target = '10.6'
  s.watchos.deployment_target = '2.0'
  s.requires_arc = true
  s.source_files = 'GSCrypto/*.{h,m}'
end
