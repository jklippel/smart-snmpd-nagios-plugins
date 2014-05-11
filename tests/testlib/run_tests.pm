package run_tests;

use strict;
use warnings;
use vars qw(@EXPORT @EXPORT_OK @ISA);

@ISA = qw(Exporter);

use Exporter;
use Carp;
use Test::More;
use IPC::Open3 ();

use POSIX ":sys_wait_h";
use IO::Select;
use IO::Handle;

use Scalar::Util qw(looks_like_number);

@EXPORT = qw(plugin_ok plugin_cmp_ok);
@EXPORT_OK = @EXPORT;

sub run_cmd {
    my $cmd = $_[0];
    my $res = { stdout => '', stderr => '' };

    eval {
        local $?;
        local $!;

        ref($cmd) or $cmd = [ $cmd ];
        ref($cmd) eq "ARRAY" or croak "Invalid command reference: " . ref($cmd);

        local (*IN, *OUT, *ERR);
        my $pid = IPC::Open3::open3(\*IN, \*OUT, \*ERR, @$cmd );

        my ( $rdr, $err ) = (*OUT, *ERR);
        my %hndl = ( stdout => $rdr, stderr => $err );

        my $s = IO::Select->new();
        $s->add(@hndl{'stdout', 'stderr'});

        my @ready;
        while( $pid != waitpid( $pid, WNOHANG ) ) {
            if( @ready = $s->can_read(1) ) {
                foreach my $fh (qw(stdout stderr)) {
                    my $rs = IO::Select->new();
                    $rs->add($hndl{$fh});
                    while( $rs->can_read(0) ) {
                        my $buf;
                        $hndl{$fh}->sysread( $buf, 8192 );
                        length($buf) or last;
                        $res->{$fh} .= $buf;
                    }
                }
            }
        }

        $res->{child_exit} = $?;
        $res->{exit_code} = $res->{child_exit} >> 8;
        $res->{signal_no} = $res->{child_exit} % 256;

        if( @ready = $s->can_read(0) ) {
            foreach my $fh (qw(stdout stderr)) {
                $hndl{$fh}->eof() and next;
                my $rs = IO::Select->new();
                $rs->add($hndl{$fh});
                while( $rs->can_read(0) ) {
                    my $buf;
                    $hndl{$fh}->sysread( $buf, 8192 );
                    length($buf) or last;
                    $res->{$fh} .= $buf;
                }
            }
        }
    };
    $@ and do { $res->{err_msg} = $@; $res->{exit_code} = -1; };
    return $res;
}

sub test_plugin {
    my ($plugin, $cmdtag, $result) = @_;

    my $p_ok = 1;
    ref($plugin) eq "HASH" or die "Invalid element in plugins list";
    defined($plugin->{$cmdtag}) or die "Missing $cmdtag field for plugin";
    ref($plugin->{$cmdtag}) eq "ARRAY" or die "$cmdtag field for plugin must be an ARRAY";
    defined($plugin->{SUCCEED}) or $plugin->{SUCCEED} = 1;
    alarm( 60 );
    my $result_hash = run_cmd( $plugin->{$cmdtag} );
    alarm( 0 );
    if( $result_hash->{stdout} ) {
        note($result_hash->{stdout});
    }
    if( $result_hash->{stderr} ) {
        diag($result_hash->{stderr});
    }

    my $plugcmd = join( " ", @{$plugin->{$cmdtag}} );
    defined($plugin->{NAME}) and $plugcmd = $plugin->{NAME} . " ($plugcmd)";

    $p_ok &= is( $result_hash->{err_msg}, undef, "No error executing plugin '$plugcmd'" );
    $p_ok &= cmp_ok( $result_hash->{exit_code}, $plugin->{SUCCEED} ? "<=" : ">", 4, "Executing $plugcmd succeeds" ) or do {
        diag( $result_hash->{err_msg} );
        return $p_ok;
    };
    if( $plugin->{SUCCEED} ) {
        $p_ok &= is( $result_hash->{stderr}, '', "No error running plugin '$plugcmd'" );
        # $p_ok &= is( scalar(@{$result_hash->{stdout}}), 1, "Got one line of nagios output from '$plugcmd'" );
        my @nag_info = ( $result_hash->{stdout} =~ m/^\s*(?:[-\w]+?\s+)*?(\w+)(?:(?:\s\-\s|[:])([^|]+))?\s*(?:$|(?:[|](.*))$)/ );
        $p_ok &= cmp_ok( scalar(@nag_info), ">=", 2, "Got obviously enough status elements from '$plugcmd'" );# and diag( Data::Dumper::Dumper( \@nag_info ) );
        defined($result) and "ARRAY" eq ref($result) and @$result = ($result_hash->{exit_code}, @nag_info);
    }
    else {
        defined($result) and "ARRAY" eq ref($result) and @$result = ($result_hash->{exit_code});
    }

    return $p_ok;
}

sub plugin_ok {
    my @plugins = @_;
    my @results;

    my $ok = 1;
    local $SIG{ALRM} = sub { die "alarm clock restart" };

    foreach my $plugin (@plugins) {
        $ok &= test_plugin($plugin, "CMD");
    }

    return $ok;
}

my $have_dbi = 0;

eval {
    require DBI;
    $have_dbi = DBI->VERSION();
};

sub nearly {
    my ($x, $y, $name) = @_;
    my $sx = $have_dbi ? DBI::neat($x) : Data::Dumper::Dumper($x);
    my $sy = $have_dbi ? DBI::neat($y) : Data::Dumper::Dumper($y);
    defined($name) or $name = "nearly($sx, $sy)";
    $x =~ s/^([-+]?(?:(?:\d+\.?)|(?:\d+\.\d+)|(?:\.\d+)))%?$/$1/;
    $y =~ s/^([-+]?(?:(?:\d+\.?)|(?:\d+\.\d+)|(?:\.\d+)))%?$/$1/;
    ok( looks_like_number($x) == looks_like_number($y), "$name: looks_like_number($sx) == looks_like_number($sy)" ) or return 0;
    if( looks_like_number($x) ) {
        $x < $y and return nearly( $y, $x, $name );
        my $mid = ($x + $y) / 2;
        my $smid = $have_dbi ? DBI::neat($mid) : Data::Dumper::Dumper($mid);
        my $n_ok = 1;
        $n_ok &= cmp_ok( $x * 1.03, ">=", $mid, "$name: ~$sx >= $smid" );
        $n_ok &= cmp_ok( $y / 1.03, "<=", $mid, "$name: ~$sy <= $smid" );
        return $n_ok;
    }
    else {
        return is( $x, $y, "$name: '$sx' cmp '$sy'" );
    }

    0;
}

sub plugin_cmp_ok {
    my @plugins = @_;
    my @results;

    my $ok = 1;
    local $SIG{ALRM} = sub { die "alarm clock restart" };

    foreach my $plugin (@plugins) {
        my (@oldres, @newres);
        my $p_ok = 1;
        $p_ok &= test_plugin($plugin, "OLDCMD", \@oldres);
        $p_ok &= test_plugin($plugin, "NEWCMD", \@newres);

        $ok &= $p_ok;
        $p_ok or next;

        my $plugcmd = join( " ", @{$plugin->{OLDCMD}} );
        defined($plugin->{NAME}) and $plugcmd = $plugin->{NAME} . " ($plugcmd)";

        is( $oldres[0], $newres[0] );
        {
            local $TODO = "";
            is( $oldres[1], $newres[1] );
        }
        if( is( defined($oldres[3]), defined($newres[3]), "$plugcmd: Both performance values are (not) available" ) 
         && defined($oldres[3]) ) {
            # my %oldres = map { my( $k, $v ) = split( '=', $_ ); $k => [ split( ';', $v ) ] } split( " ", $oldres[3] );
            # my %newres = map { my( $k, $v ) = split( '=', $_ ); $k => [ split( ';', $v ) ] } split( " ", $newres[3] );
            my (%oldres, %newres);
            while( $oldres[3] =~ m/\s*([^=]+)=(\S*)(?:\s+|$)/g ) {
                $oldres{$1} = [ split( ';', $2 ) ];
            }
            while( $newres[3] =~ m/\s*([^=]+)=(\S*)(?:\s+|$)/g ) {
                $newres{$1} = [ split( ';', $2 ) ];
            }

            foreach my $k (keys %oldres) {
                ok( defined( $newres{$k} ), "$plugcmd: defined \$newres{$k}" ) or next;
                cmp_ok( scalar( @{$oldres{$k}} ), "==", scalar( @{$newres{$k}} ), "$plugcmd: scalar(\@\$oldres{$k}) == scalar(\@\$newres{$k})" ) or next;
                for( my $i = 0; $i < scalar(@{$newres{$k}}); ++$i ) {
                    nearly( $oldres{$k}[$i], $newres{$k}[$i], "$plugcmd: \$oldres{$k}[$i] == \$newres{$k}[$i]" );
                }
            }
        }
    }

    return $ok;
}

1;
