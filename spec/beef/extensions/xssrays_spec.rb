
#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
require 'extensions/xssrays/extension'

RSpec.describe 'BeEF Extension XSSRays' do
  before(:all) do
    @config = BeEF::Core::Configuration.instance
    @config.load_extensions_config
  end

  it 'loads configuration' do
    config = @config.get('beef.extension.xssrays')
    expect(config).to have_key('enable')
    expect(config).to have_key('clean_timeout')
    expect(config).to have_key('cross_origin')
    expect(config).to have_key('require_execution_proof')
  end

  it 'interface' do
    xssrays = BeEF::Extension::Xssrays::API::Scan.new
    expect(xssrays).to respond_to(:start_scan)
    expect(xssrays).to respond_to(:add_to_body)
  end

  describe BeEF::Extension::Xssrays::Proof do
    it 'accepts the proof produced by the browser callback' do
      token = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
      expect(described_class.valid?(token, token.reverse)).to be(true)
    end

    it 'rejects a raw reflected token' do
      token = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
      expect(described_class.valid?(token, token)).to be(false)
    end

    it 'rejects malformed or missing proofs' do
      expect(described_class.valid?('short', 'tros')).to be(false)
      expect(described_class.valid?(nil, nil)).to be(false)
    end

    it 'rejects palindromic tokens' do
      token = 'a' * 32
      expect(described_class.valid?(token, token)).to be(false)
    end
  end
end
