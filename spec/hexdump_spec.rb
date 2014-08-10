# coding: utf-8
require 'spec_helper'
require 'hexdump'

describe 'HexDump' do
  it 'encode' do
    str = "\032l\277\370\2429\216\236\351[{\{\262\350\274\376"
    str.force_encoding('BINARY') if str.respond_to?(:force_encoding)
    expect(HexDump.encode(str)).to eq ["00000000  1a6cbff8 a2398e9e e95b7b7b b2e8bcfe   .l...9...[{{...."]
  end
end
