#!/usr/bin/ruby
require 'rubygems'
# DEBUG:
require '/home/ldap/luke.jolly/logmailer/logmailer_lib.rb'
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
# :entry_search => Array of regex. Looks in each entry found for each of these regex's. #
#             Only one regex needs to match the entry to HIGH priority. If an entry     #
#             doesn't match any of these, doesn't match any rejects, but matches one of #
#             the token_scans it is LOW priority.                                       #
#                                                                                       #
# :entry_reject => Array of regex. If an entry matched any of these, it is rejected     #
#             from both HIGH and LOW.                                                   #
#                                                                                       #
# :entry_tag => Array of arrays.  Each array's first element is a string which is the   #
#             tag. The second element is a regex. All HIGH and LOW entries are checked. # 
#             If there's a match, the entry's tag becomes the corresponding tag. If     #
#             there is no match, the entry's tag is it's priority (either "HIGH" or     #
#             "LOW"). This tag is put in the subject line of emails to help with rules. #
#                                                                                       #
# :token_scan => Array of regex. Each entry which passed :entry_search/:entry_reject is #
#             is matched against these tokens. Each needs some sort of matching in them #
#             (aka, parenthesis). The elements matched will be used to build the hash   #
#             which determines if this identical (or similar enough) entry has already  #
#             been seen (used for summary mode)                                         #
#                                                                                       #
#########################################################################################

LOG       = true
LOGDIR    = "/home/ldap/luke.jolly/logmailer/logs"

CONFIG = [

#    <%if node[:roles].include? "front_end_nodes" -%>
    {
        :name           => "php_log",
        :files          => ls_directory("/var/log/php/").grep(/_log$/),
        :delimiters     => [ /^\[[0-9]{2}\-[A-Za-z]{3}\-[0-9]{4}/ ],
        :entry_search   => [ /fatal/i, 
                             /gave bad values for recording offline streams/ ], #For skyler
        :entry_reject   => [ /HTTPS\snot\srequired\sfor\scowbell\smethod/ ], 
        :entry_tag      => [ ["IGNORE", /PHP.Notice.*Undefined.index.*CachedFileHosts.*StreamEx.php.*160/i], 
                             ["IGNORE", /PHP.Notice.*Undefined.index.*FileID.*StreamEx.php.*159/i],
                             ["IGNORE", /PHP.Notice.*STREAM.ERROR.*Could.not.find.valid.Stream.Server.*StreamEx.php.*174/i]
                           ],
        :token_scan     => [ /(notice|error|warning):\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/i,
                             /API key ID ([0-9]+)/,
                             /(Attacker\!\!)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/i,
                             /(\!\!\!ATTACKER BANNED\!\!\!\!)\s+([^ ]+)\s+([^ ]+)/i,
                             /(IP\saddress)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ], #For skyler
        :low_thresh     => 100
    },
    {
        :name           => "nginx_log",
        :files          => [ "/var/log/nginx/error.log" ],
        :delimiters     => [ /[^ ]+\s[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}/ ],
        :entry_search   => [ /\[crit\]/, 
                             /\[error\]\s.+?:.*?[0-9]*? connect\(\)/ ],
        :entry_reject   => [ /unlink\(\)/, 
                             /SSL. error.1408F06B.SSL routines.SSL3_GET_RECORD.bad decompression/ ],
        :entry_tag      => [],
        :token_scan     => [ /\[(crit|error)\]\s+([^ ]+)/ ],
        :low_thresh     => 100
    },
#    <% end -%>

    #<%if node[:roles].include? "stream_nodes" -%>
    #{
    #    :name           => "php_log",
    #    :files         => ls_directory("/var/log/php/").grep(/_log$/),
    #    :delimiters     => [ /^\[/ ],
    #    :entry_search   => [ /fatal/i ],
    #    :entry_reject   => [], 
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
    #    :entry_reject  => [ /unlink\(\)/ ],
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
#        :entry_reject   => [],
#        :entry_tag      => [],
#        :token_scan     => [ /ERROR\s+([^ ]+)/ ],
#        :low_thresh     => 1000
#    },
#    <% end -%>


    #<%if node[:roles].include? "mongo_nodes" -%>
    #{
    #    :name         => "mongo_log",
    #    :files        => [ "/var/log/mongo/mongod.log",
    #                       "/var/log/mongo/mongod1.log",
    #                       "/var/log/mongo/mongod2.log",
    #                       "/var/log/mongo/mongod3.log" ],
    #    :delimiters   => [ /\n/ ],
    #    :entry_search => [ / query .+(\d+)ms$/i ],
    #    :entry_reject => [ /writebacklisten/ ],
    #    :entry_tag      => [],
    #    :token_scan   => [ /query ([^ ]+)/ ],
    #    :low_thresh     => 0
    #},
    #<% end -%>

#    <%if node[:roles].include? "manatee_test_nodes" -%>
    {
        :name           => "manatee_test_nodes",
        :files          => [ "/tmp/manatee_test" ],
        :delimiters     => [ /\n/ ],
        :entry_search   => [ /./ ],
        :entry_reject   => [],
        :entry_tag      => [],
        :token_scan     => [ /([^ ]+)/ ],
        :low_thresh     => 0
    },
#    <% end -%>

#    {
#        :name           => "disk_subsystem",
#        :files          => [ "<%= node[:disk_subsystem][:log] %>" ],
#        :delimiters     => [ /\n/ ],
#        :entry_search   => [ /./],
#        :entry_reject   => [],
#        :entry_tag      => [],
#        :token_scan     => [ /([^:]+):/ ],
#        :low_thresh     => 0
#    },
    {
        :name           => "chef_log",
        :files          => [ "/var/log/chef/client.log" ],
        :delimiters     => [ /^\[.+\]/ ],
        :entry_search   => [ /FATAL:/ , /Transaction Check Error:/],
        :entry_reject   => [ /Sleeping\sfor\s[0-9]+\sseconds/i ],
        :entry_tag      => [],
        :token_scan     => [ /FATAL:\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/ ],
        :low_thresh     => 0
    }
]

CONFIG.each do |log_config|
    config_check?(log_config)
end

# TODO: move this into the main?
$pids = {}
