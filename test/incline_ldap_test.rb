require 'test_helper'

class InclineLdapTest < Minitest::Test
  
  def setup
    @config = {
        host: 'ldap.forumsys.com',
        port: 389,
        ssl: false,
        base_dn: 'dc=example,dc=com',
        browse_user: 'cn=read-only-admin,dc=example,dc=com',
        browse_password: 'password',
        auto_create: true,
        auto_activate: true
    }
  end
  
  def test_should_not_authenticate_without_password
    aa = InclineLdap::AuthEngine.new(@config)
    euler = 'euler@ldap.forumsys.com'
    
    assert aa
    assert_nil aa.authenticate(euler, '', '127.0.0.1')
  end
  
  def test_should_connect_and_authenticate
    aa = InclineLdap::AuthEngine.new(@config)
    euler = 'euler@ldap.forumsys.com'
    einstein = 'einstein@ldap.forumsys.com'
    frank = 'frankenstein@ldap.forumsys.com'

    assert aa
    # should not be able to login as "Euler" with incorrect password.
    assert_nil aa.authenticate(euler, 'wrong', '127.0.0.1')
    # should be able to login as "Euler" with correct password.
    assert aa.authenticate(euler, 'password', '127.0.0.1')
    # should not be able to login as "Frankenstein" at all.
    assert_nil aa.authenticate(frank, 'password', '127.0.0.1')
    # should be able to login as 'Einstein'.
    assert aa.authenticate(einstein, 'password', '127.0.0.1')
  end
  
  def test_should_raise_error_for_invalid_config
    [
        [ :host, nil ],
        [ :host, '' ],
        [ :host, '   ' ],
        [ :port, -1 ],
        [ :port, 65536 ],
        [ :base_dn, nil ],
        [ :base_dn, '' ],
        [ :base_dn, '   ' ],
        [ :browse_user, nil ],
        [ :browse_user, '' ],
        [ :browse_user, '   ' ],
        [ :browse_password, 'invalid-password' ]
    ].each do |(k,v)|
      assert_raises(InclineLdap::AuthEngine::ConnectionError) do
        InclineLdap::AuthEngine.new(@config.merge({ k => v }))
      end
    end
  end
  
  
  
end
