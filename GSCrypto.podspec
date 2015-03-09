Pod::Spec.new do |s|
  s.name         = 'GSCrypto'
  s.version      = '1.2.1'
  s.author       = 'GyazSquare'
  s.license      = { :type => 'MIT' }
  s.homepage     = 'https://github.com/GyazSquare/GSCrypto'
  s.source       = { :git => 'https://github.com/GyazSquare/GSCrypto.git', :tag => '1.2.1' }
  s.summary      = 'A simple digest library for iOS and OS X.'
  s.ios.deployment_target = '5.0'
  s.osx.deployment_target = '10.6'
  s.requires_arc = true
  s.source_files = 'GSCrypto/*.{h,m}'
end
