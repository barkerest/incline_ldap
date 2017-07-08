require 'net-ldap'
require 'incline'
require 'securerandom'

module InclineLdap

  ##
  # Defines an engine used to authenticate a user against an LDAP provider.
  class AuthEngine < ::Incline::AuthEngineBase

    ##
    # An error raised when attempting to establish a connection to the LDAP provider.
    ConnectionError = Class.new(StandardError)

    ##
    # Raised when a configuration value is invalid.
    InvalidConfiguration = Class.new(ConnectionError)

    ##
    # Raised when the configuration looks good but we are still unable to connect.
    BindError = Class.new(ConnectionError)

    ##
    # Creates a new LDAP authentication engine.
    #
    # Valid options:
    # host::
    #     The LDAP host name or IP address.  (required)
    # port::
    #     The port to connect to (defaults to 389 for non-ssl and 636 for ssl).
    # ssl::
    #     Should SSL be used for the connection (recommended, default is true).
    # base_dn::
    #     The base DN to search within when looking for user accounts.  (required)
    # browse_user::
    #     A user to log in as when looking for user accounts.  (required)
    # browse_password::
    #     The password for the browse_user.
    # email_attribute::
    #     The attribute to use when looking for user accounts (default is 'mail').
    # auto_create::
    #     If true, users are automatically created when they successfully authenticate against the LDAP provider for
    #     the first time.
    # auto_activate::
    #     If this and auto_create are both true, then newly created users will be activated.  If auto_create is false,
    #     this option has no effect.  If this is false and auto_create is true, newly created users will need to
    #     activate their accounts as if they had signed up.
    #
    def initialize(options = {})
      @options = {
          ssl: true,
          email_attribute: 'mail'
      }.merge(options || {})

      @options[:port] = @options[:port].to_s.to_i unless @options[:port].is_a?(::Integer)

      if @options[:port] == 0
        @options[:port] = (@options[:ssl] ? 636 : 389)
      end

      raise InvalidConfiguration, "Missing value for 'host' parameter." if @options[:host].blank?
      raise InvalidConfiguration, "The value for 'port' must be between 1 and 65535." unless (1..65535).include?(@options[:port])
      raise InvalidConfiguration, "Missing value for 'base_dn' parameter." if @options[:base_dn].blank?
      raise InvalidConfiguration, "Missing value for 'email_attribute' parameter." if @options[:email_attribute].blank?
      raise InvalidConfiguration, "Missing value for 'browse_user' parameter." if @options[:browse_user].blank?

      ldap_opt = {
          host: @options[:host],
          port: @options[:port],
          base: @options[:base_dn],
          auth: {
              method: :simple,
              username: @options[:browse_user],
              password: @options[:browse_password]
          }
      }

      if @options[:ssl]
        @options[:ssl] = @options[:ssl].to_sym if @options[:ssl].is_a?(::String)

        unless [:simple_tls, :start_tls].include?(@options[:ssl])
          @options[:ssl] =
              if @options[:port] == 389
                :start_tls
              else
                :simple_tls
              end
        end

        ldap_opt[:encryption] = { method: @options[:ssl] }
      end

      ::Incline::Log::debug "Creating new LDAP connection to #{@options[:host]}:#{@options[:port]}..."
      @ldap = Net::LDAP.new(ldap_opt)

      ::Incline::Log::debug 'Binding to LDAP server...'
      raise BindError, "Failed to connect to #{@options[:host]}:#{@options[:port]}." unless @ldap.bind

      ::Incline::Log::info "Connected to LDAP host #{@options[:host]}:#{@options[:port]}."
    end

    ##
    # Gets the host name or IP address for this LDAP authenticator.
    def host
      @options[:host]
    end

    ##
    # Gets the host port for this LDAP authenticator.
    def port
      @options[:port]
    end

    ##
    # Gets the SSL method for this LDAP authenticator.
    def ssl
      @options[:ssl]
    end

    ##
    # Gets the Base DN for this LDAP authenticator.
    def base_dn
      @options[:base_dn]
    end

    ##
    # Gets the email attribute name for this LDAP authenticator.
    def email_attribute
      @options[:email_attribute]
    end

    ##
    # Authenticates a user against an LDAP provider.
    def authenticate(email, password, client_ip)
      ldap_filter = "(&(objectClass=user)(#{@options[:email_attribute]}=#{email}))"

      reset_ldap!

      search_result = @ldap.search(filter: ldap_filter)

      if search_result && search_result.count == 1
        user = ::Incline::User.find_by(email: email)
        if @options[:auto_create] && user.nil?
          rpwd = ::SecureRandom.urlsafe_base64(48)
          ::Incline::Recaptcha::pause_for do
            user =
                ::Incline::User.create(
                    email: email,
                    password: rpwd,
                    password_confirmation: rpwd,
                    name: search_result[:name].first,
                    recaptcha: 'none',
                    enabled: true,
                    activated: !!@options[:auto_activate],
                    activated_at: (@options[:auto_activate] ? Time.now : nil)
                )
            user.send_activation_email client_ip
          end
        end
        if user
          unless user.enabled?
            add_failure_to user, '(LDAP) account disabled', client_ip
            return nil
          end
          entry = @ldap.bind_as(filter: ldap_filter, password: password)
          if entry && entry.count == 1
            add_success_to user, '(LDAP)', client_ip
          else
            add_failure_to user, '(LDAP) invalid password', client_ip
          end
        end
      end
      add_failure_to email, 'invalid email', client_ip
      nil
    end

    private

    def reset_ldap!
      @ldap.auth @options[:browse_user], @options[:browse_password]
      @ldap.bind
    end

  end
end