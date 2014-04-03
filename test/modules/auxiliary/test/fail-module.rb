##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'nokogiri'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'        => 'Test module to Fail Msftidy',
      #
      'Description' => %q{
        this module boasts some exciting msftidy warns and errors.
      },
      'Author'      => '@toÐb',
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )
    register_advanced_options(
      [
        OptInt.new('TIMEOUT', [ true, 'Default timeout.', 0])
      ], self.class
    )

  end

  def run_host(ip)
    do_stuff_and_things
  end

  def do_stuff_and_things
    start_telnet_session(rhost,rport,user,pass)
  end

end
