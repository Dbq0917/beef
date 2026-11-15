#
# Copyright (c) 2006-2026 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - https://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
  module Extension
    module Xssrays
      # Validates the challenge-response sent by the browser when an injected
      # vector actually executes. A raw reflection of the callback URL cannot
      # produce the reversed token because that operation runs client-side.
      module Proof
        TOKEN_PATTERN = /\A[a-z0-9]{32}\z/

        def self.valid?(token, proof)
          token = token.to_s
          proof = proof.to_s

          return false unless TOKEN_PATTERN.match?(token)

          expected = token.reverse
          return false if expected == token

          proof == expected
        end
      end
    end
  end
end
