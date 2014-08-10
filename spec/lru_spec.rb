# coding: utf-8
require 'spec_helper'

describe HTTPClient::LRUCache do
  before :each do
    @cache = subject.class.new(ttl: 1, max_size: 2, soft_ttl: 2)
  end
  
  it 'expires values' do
    expect(@cache.fetch('test') { 2 }).to eq(2)
    expect(@cache.fetch('test') { 3 }).to eq(2)
    sleep 2
    expect(@cache.fetch('test') { 4 }).to eq(4)
  end
end

