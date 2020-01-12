require 'spec_helper'

describe 'falco' do
  context 'with defaults for all parameters' do
    it { should contain_class('falco') }
  end
end
