#!/usr/bin/ruby
require 'rubygems'
# DEBUG:
require '/home/ldap/luke.jolly/git/logmailer/logmailer_lib.rb'
#require '<%= node[:logmailer][:full_path]+node[:logmailer][:lib] %>'

#########################################################################################
#                                                                                       #
# :name => The name of this log. Doesn't have to correspond to anything, is only used   #
#             for debugging                                                             #
#                                                                                       #
# :files => Array of full-path files. Use the Dir class if you want everything in a     #
#             directory                                                                 #
#                                                                                       #
# :delimiters => Array of delimiters (regex). Logmailer looks at each line of the file  #
#             as it comes in. If it finds one of these delimiters it knows the last     #
#              entry has ended and the next one has started                             #
#                                                                                       #
# :entry_search => Array of regex. If an entry matches any of these regexes, and        #
#             none of the reject_global or reject_high regexes, it is HIGH priority.    #
#             If an entry doesn't match any of these, doesn't match reject_global, but  #
#             still matches one of the token_scans it is LOW priority (doesn't get      #
#             emailed unless it breaks low_thresh in a minute)                          #
#                                                                                       #
# :reject_global => Array of regex. If an entry matched any of these, it is rejected    #
#             from both HIGH and LOW.                                                   #
#                                                                                       #
# :reject_high => Array of regex.  If an entry matches any of these, it is rejected     #
#             from HIGH and treated as LOW priority.                                    #
#                                                                                       #
# :entry_tag => Array of arrays.  Each array's first element is a string which is the   #
#             tag. The second element is a regex. All HIGH and LOW entries are checked. # 
#             If there's a match, the entry's tag becomes the corresponding tag. If     #
#             there is no match, the entry's tag is it's priority (either "HIGH" or     #
#             "LOW"). This tag is put in the subject line of emails to help with rules. #
#             This does not change what priority the entry is sorted as.                #
#                                                                                       #
# :token_scan => Array of regex. Each entry whether HIGH or LOW priority is matched     #
#             against these tokens. Each needs some sort of matching in them            #
#             (aka, parenthesis). The elements matched will be used to build the hash   #
#             which determines if this identical (or similar enough) entry has already  #
#             been seen (used for summary mode). Thus if two entries result in the same #
#             tokens they are grouped as the same error.                                #
#                                                                                       #
#########################################################################################

LOG       = true
LOGDIR    = "/home/ldap/luke.jolly/git/logmailer/logs"

CONFIG = [

#    <%if node[:roles].include? "front_end_nodes" -%>
#    {
#        :name           => "php_log",
#        :files          => ls_directory("/var/log/php/").grep(/_log$/),
#        :delimiters     => [ /^\[[0-9]{2}\-[A-Za-z]{3}\-[0-9]{4}/ ],
#        :entry_search   => [ /fatal/i, 
#                             /gave bad values for recording offline streams/ ], #For skyler
#        :reject_global  => [ /HTTPS\snot\srequired\sfor\scowbell\smethod/ ], 
#        :reject_high    => [ /PHP.Notice.*PHP Fatal.error.*fake.*kinesis.save.error.for..Array/m,
#                             /PHP.Notice.*PHP Fatal.error.*fake.*kinesis.missing.parameters.from.request/,
#                             /PHP.Fatal.error.*Allowed.memory.size.of.*exhausted/,
#                             /PHP.Fatal.error.*Uncaught.exception.*Exception.*with.message.*Unknown.Twitter.error/
#                           ],
#        :entry_tag      => [ ["IGNORE", /PHP.Notice.*Undefined.index.*CachedFileHosts.*StreamEx.php/i], 
#                             ["IGNORE", /PHP.Notice.*Undefined.index.*FileID.*StreamEx.php/i],
#                             ["IGNORE", /PHP.Notice.*STREAM.ERROR.*Could.not.find.valid.Stream.Server.*StreamEx.php/i],
#                             ["IGNORE", /PHP.Notice.*PHP Fatal.error.*fake.*kinesis.save.error.for..Array/],
#                             ["IGNORE", /PHP.Notice.*PHP Fatal.error.*fake.*kinesis.missing.parameters.from.request/]
#                             #["IGNORE", /PHP.Fatal.error.*Allowed.memory.size.of.*exhausted/]
#                           ],
#        :token_scan     => [ /(notice|error|warning):\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/i,
#                             /API key ID ([0-9]+)/,
#                             /(Attacker\!\!)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/i,
#                             /(\!\!\!ATTACKER BANNED\!\!\!\!)\s+([^ ]+)\s+([^ ]+)/i,
#                             /(IP\saddress)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ], #For skyler
#        :low_thresh     => 100
#    },
#    {
#        :name           => "nginx_log",
#        :files          => [ "/var/log/nginx/error.log" ],
#        :delimiters     => [ /[^ ]+\s[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}/ ],
#        :entry_search   => [ /\[crit\]/, 
#                             /\[error\]\s.+?:.*?[0-9]*? connect\(\)/ ],
#        :reject_global  => [ /unlink\(\)/, 
#                             /SSL. error.1408F06B.SSL routines.SSL3_GET_RECORD.bad decompression/ ],
#        :reject_high    => [],
#        :entry_tag      => [],
#        :token_scan     => [ /\[(crit|error)\]\s+([^ ]+)/ ],
#        :low_thresh     => 100
#    },
#    <% end -%>

    #<%if node[:roles].include? "stream_nodes" -%>
    #{
    #    :name           => "php_log",
    #    :files         => ls_directory("/var/log/php/").grep(/_log$/),
    #    :delimiters     => [ /^\[/ ],
    #    :entry_search   => [ /fatal/i ],
    #    :reject_global   => [],
    #    :reject_high    => [],
    #    :entry_tag      => [],
    #    :token_scan     => [ /error:\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/i ],
    #    :low_thresh     => 0
    #},
    #    <%if not node[:hostname].eql? 'RHL036' -%>
    #{
    #    :name           => "nginx_log",
    #    :files          => [ "/var/log/nginx/error.log" ],
    #    :delimiters     => [ /[^ ]+\s[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}/ ],
    #    :entry_search   =>  [ 
    #                            /\[crit\]/, 
    #                            /\[error\] .+?:.*?[0-9]*? connect\(\)/,
    #                            /\[error\] .+?:.*?[0-9]*? open\(\)/ 
    #                        ],
    #    :reject_global  => [ /unlink\(\)/ ],
    #    :reject_high    => [],
    #    :entry_tag      => [],
    #    :token_scan     => [ /\[(crit|error)\]\s+([^ ]+)/ ],
    #    :low_thresh     => 0
    #},
    #    <% end -%>
    #<% end -%>

#    <%if node[:roles].include? "hadoop" -%>
#    {
#        :name           => "hadoop_log",
#        :files          => ls_directory("logs/").grep(/.log$/),
#        :delimiters     => [ /[^ ]+\s[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}/ ],
#        :entry_search   => [ /ERROR/i ],
#        :reject_global  => [],
#        :reject_high    => [],
#        :entry_tag      => [],
#        :token_scan     => [ /ERROR\s+([^ ]+)/ ],
#        :low_thresh     => 1000
#    },
#    <% end -%>


#    <%if node[:roles].include? "mongo_nodes" -%>
    {
        :name           => "mongo_log",
        :files          => [ "/var/log/mongo/mongod.log",
                             "/var/log/mongo/mongod1.log",
                             "/var/log/mongo/mongod2.log",
                             "/var/log/mongo/mongod3.log" ],
        :delimiters     => [ /\n/ ],
        :entry_search   => [],
        :reject_global  => [],
        :reject_high    => [],
        :entry_tag      => [],
        :token_scan     => [ /\[.*\].([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ],
        :low_thresh     => 20 
    },
#    <% end -%>

#    <%if node[:roles].include? "manatee_test_nodes" -%>
#    {
#        :name           => "manatee_test_nodes",
#        :files          => [ "/tmp/manatee_test" ],
#        :delimiters     => [ /\n/ ],
#        :entry_search   => [ /./ ],
#        :reject_global  => [],
#        :reject_high    => [],
#        :entry_tag      => [],
#        :token_scan     => [ /([^ ]+)/ ],
#        :low_thresh     => 0
#    },
#    <% end -%>

    {
        :name           => "disk_subsystem",
        :files          => [ "/var/log/disk_subsystem.log" ],
        :delimiters     => [ /\n/ ],
        :entry_search   => [ /./],
        :reject_global  => [],
        :reject_high    => [],
        :entry_tag      => [],
        :token_scan     => [ /([^:]+):/ ],
        :low_thresh     => 0
    },
    {
        :name           => "chef_log",
        :files          => [ "/var/log/chef/client.log" ],
        :delimiters     => [ /^\[.+\]/ ],
        :entry_search   => [ /FATAL:/ , /Transaction Check Error:/],
        :reject_global  => [ /Sleeping\sfor\s[0-9]+\sseconds/i ],
        :reject_high    => [],
        :entry_tag      => [],
        :token_scan     => [ /FATAL:\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ],
        :low_thresh     => 0
    }
]

CONFIG.each do |log_config|
    config_check?(log_config)
end
