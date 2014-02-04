# coding: utf-8
require 'spec_helper'

describe HTTPClient::LRUCache do
  before :each do
    @cache = subject.class.new(ttl: 3, max_size: 2, soft_ttl: 2)
  end
  
  it 'expires values' do
    @cache.fetch 'test' do
      2
    end.should eq 2
    @cache.fetch 'test' do
      3
    end.should eq 2
    sleep 4
    @cache.fetch 'test' do
      4
    end.should eq 4
  end
end

