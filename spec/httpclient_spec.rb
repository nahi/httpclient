# coding: utf-8
require 'spec_helper'

describe HTTPClient do
  describe 'GET' do
    it 'performs normal GET' do
      HTTPClient.new.get(@srv.u('servlet')) do |s|
        s.should eq 'get'
      end
    end
  end
end
