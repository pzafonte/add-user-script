#!/usr/bin/perl

use strict qw(refs);
use warnings;

use Getopt::Std;
use Authen::Krb5;

#### error codes ####
use constant ERR_NONE             => 0;
use constant ERR_SYSFAIL          => 1;
use constant ERR_RETRY            => 2;
use constant ERR_NOTFOUND         => 3;
use constant ERR_INUSE            => 4;
use constant ERR_UNIMPLEMENTED    => 5;
use constant ERR_INTERNAL         => 6;
use constant ERR_INPUT            => 7;
use constant ERR_EXTERNAL         => 8;

#### account COMPONENT statuses ####
use constant STATUS_FREE   => 0;
use constant STATUS_INUSE  => 1;
use constant STATUS_UNINIT => 3;

#### stuff to help store the CWID info ####
use constant CWID_STAT_UNINIT     => 0;
use constant CWID_STAT_FOUND      => 1;
use constant CWID_STAT_NOTFOUND   => 2;
use constant CWID_STAT_INPUT      => 3;
use constant CWID_STAT_NA         => 4;


#### account (as a whole) statuses ####
use constant ACCNTSTAT_FREE       => 0;
use constant ACCNTSTAT_COMPLETE   => 1; 
use constant ACCNTSTAT_INCOMPLETE => 2;
use constant ACCNTSTAT_UNINIT     => 3;

#### some regexes  ####
use constant ZHOME_REGEX   => qr(^xraid0-1/tank/home/[a-z]\.?[a-z0-9-_]*$);
use constant NAME_REGEX    => qr/^[A-Z]([A-Za-z .\/\-_])*$/;
use constant USER_REGEX    => "^[a-z]\.?[-a-z0-9_]{0,14}\$"; 
use constant UID_REGEX     => "^[1-9][0-9]{3,5}";
use constant QUOTA_REGEX   => qr/[1-9][0-9]*([Kk]|[Gg]|[Mm]|[Tt])/;
use constant EMAIL_REGEX   => qr/.*@.*\..*/;

#TODO why does this work as a scalar but not a constant?
my $CWID_REGEX = qr/^(10[0-9]{6})|(9999[6,7]{4})$/;

#### default zfs home prefix to username ####
use constant ZHOME_BASE    => "xraid0-1/tank/home";

#### some limits ####
use constant UID_MIN       => 10000;
use constant UID_MAX       => 4294967296;    #2^32 

####  debug levels  ####
use constant DBL_NONE => 0;        #no debug output
use constant DBL_DIAG => 1;        #diagnostic messages
use constant DBL_ALG  => 2;        #internal algorithm outputs
use constant DBL_FT   => 3;        #function trace

#### for bookkeeping when setting GID ####
use constant GID_NONE => -1;

#### execution mode flags ####
use constant MODE_INIT         => 0b1;     #perhaps moribund; no references to this anywhere TODO
use constant MODE_REAL         => 0b10;    #else MODE is TEST
use constant MODE_BATCH        => 0b100;   #else MODE is interactive
use constant MODE_ACCEPT       => 0b1000;  #else MODE is to prompt / ask

### what principal needs to have currently valid credentials to execute ###
use constant KERB_CREDS_NEEDED => 'sysadmin@PHY.STEVENS-TECH.EDU';

use constant OFF_CAMPUS_PIPELINE_ID => '[off-campus-pipeline-id-token]';
use constant CWID_OFF_CAMPUS =>  99996666;
use constant CWID_UNINIT => 99990000;

####  FILES  ####
use constant NEW_ACCOUNT_BLURB_FILE => "/root/bin/addu/New_Account_Blurb.txt";
use constant DEFAULT_TICKET_NOTE_FILE => "/root/bin/addu/.adduser$$.note";
use constant USERNAME_TOKEN => qw(<username>);
use constant PASS_STRING_TOKEN => qw(<pass_string>);

#used for updating the ticket via email
use constant DEFAULT_MAILUTILS_MAIL => "/usr/bin/mail";
use constant MAIL_ADDR_SRCIT_TECH => 'pzafonte@stevens.edu';
use constant MAIL_ADDR_HELPDESK => 'pzafonte@stevens.edu';



################################################################################
#                                                                              #
#                          SUBROUTINE PROTOTYPES / DECLARATIONS                #
#                                                                              #
################################################################################
#### output subroutines ####
sub debugOutput($$;);
sub printAccountStatus($;);
sub printUsage(;);
sub printAccount($;);

#### things that get operational user input ####
sub getInfo($;);
sub confirmInfo($;);
sub changeInfo($;);
sub processOptions($$;);

#### more specific user input ####
sub getEmailAddress($;);
sub getUserName($;);
sub getFLNames($;);
sub getLoginShell($;);
sub getZFSHome($;);
sub getPassword($;);
sub getDepartment($;);
sub getUidNumber($;);
sub getGidNumber($;);

#### helper subroutines ####
sub lookupLoginShells(;);
sub verifyInputFormat($$;);
sub verifyName($;);
sub verifyUidNumber($;);
sub findFirstFreeUid($$);
sub lookupGids(;);
sub checkSubStatus($$;);
sub checkExistingCreds($;);

#### Top-level Account functions ####
sub checkAccountStatus($;);
sub getAccountStatus($;);
sub makeAccount($;);
sub getAccountComponent($$;);
sub verifyAccount($;);
sub verifyAutomount($;);

#### general LDAP ####
sub getLdapInfo($;);
sub addUserToLdap($;);

#### LDAP Account ####
sub getLdapAccountComponent($;);
sub ldapLoginNameFree($;);
sub ldapUIDFree($;);
sub lookupLdapUids(;);
sub verifyLdapAccount($;);
sub createAccountLdif($;);

#### LDAP Automount ####
sub ldapAutomountFree($;);
sub getLdapAutomountComponent($;);
sub createAutomountLdif($;);

#### Kerberos ####
sub getKrb5Policy($;);
sub getKerberosComponent($;);
sub lookupKrb5Policies($;);
sub kerberosPrincipalFree($;);
sub verifyKrb5Princ($;);
sub addPrincipalToKerberos($;);
sub getKerberosInfo($;);

#### Zfs ####
sub createZfs($;);
sub getZfsQuota($;);
sub getZfsInfo($;);
sub zfsFree($;);
sub verifyZfs($;);
sub getZfsComponent($;);

#### door access queue ####
sub addToDoorAccessQueue($;);
sub verifyDoorAccessQueue($;);

#### Exec Mode Flags ####
sub checkExecMode($;);
sub setExecMode($;);

#### pipelineID + CWID DB ####
sub logAccountCreation($;);
sub addToCwidDb($;);
sub getpipelineID($;);

#### ticketing system ####
sub getTicketNumber(;);
sub updateTicket($$$;);
sub outputTicketBlurb($$;);

sub verifyBatchOptions($$;);
#end function / procedure declarations

################################################################################
#                                                                              #
#                                 GLOBALS                                      #
#                                                                              #
################################################################################

my $debugLevel;
$debugLevel = DBL_NONE;

#### bit0: uninit/init, bit1: test/real, bit2: batch/interactive ####
my $execMode =0b000;

#TODO- unify the defined constants and these global variables
my $EMAIL_QUEUE_FILE = "/export/srcit-dist/adduser/emailNotification/usernames";
my $DAQ_FILENAME  = "/export/srcit-dist/adduser/doorAccess/accessQueue";
my $CWID_FILENAME = "/root/dev/addu/single/CWIDs.txt";

my $ADDUSER_CWID_AWK_SCRIPT = "/root/dev/addu/single/addu_cwid.awk";
my $ADDUSER_FLNAMES_AWK_SCRIPT = "/root/dev/addu/single/addu_cwid_fl_names.awk";
my $ADDUSER_CWID_LIST  = "/root/dev/addu/single/CWIDs.txt";

my $kadmin = '/usr/sbin/kadmin';
my $ldapsearch = '/opt/local/bin/ldapsearch' ;
my $ldapadd = '/opt/local/bin/ldapadd' ;
my $automountLdifDir = "/root/ldap/ldif/ou/auto.home/";
################################################################################
#                                                                              #
#                          Account Structures / DATA STRUCTURES                #
#                                                                              #
################################################################################
####  TODO- add function pointers for a Status Method     ####
####  This will make it easier to loop over the statuses  ####

my %ldapAccount = (
        cn            => "",
        sn            => "",
        uid           => "",
        uidNumber     => "",
        gidNumber     => "",
        homeDirectory => "",
        loginShell    => "/bin/bash",
        gecos         => "",
        mail          => "",
        pipelineID    => "",
        cwid          => CWID_UNINIT,
        cwid_status   => CWID_STAT_UNINIT,
        status        => STATUS_UNINIT
);

my %ldapAutomount = (
        automountInformation => "",
        status               => STATUS_UNINIT
);

my %krb5Princ = (
        principal     => "",
        policy        => "user",
        realm         => "PHY.STEVENS-TECH.EDU",
        password      => "",
        status        => STATUS_UNINIT
);

my %zfs = (
        zfsPath       => "",
        mountpoint    => "",   
        quota         => "1G",
        status        => STATUS_UNINIT
);


my %account = (
        ldapAccount   => \%ldapAccount,
        ldapAutomount => \%ldapAutomount,
        krb5Princ     => \%krb5Princ,
        zfs           => \%zfs,
        status        => ACCNTSTAT_UNINIT,
);


####  an array of group names that will be passed to the ldaptool  ####
####  for adding groups                                            ####

my @supplementalGroups;

################################################################################
#                                                                              #
#                           Options Structure / DATA STRUCTURES                #
#                                                                              #
################################################################################

my %options = (
    "b"  => 0,           #Batch mode
    "c"  => 0,           #Cwid
    "p"  => 99990000,    #pipelineID
    "f"  => 0,           #Full name
    "g"  => 0,           #Primary Group
    "d"  => 0,           #Department (Code)
    "T"  => 0,           #Test mode
    "t"  => 0,           #ticket number 
    "u"  => 0,           #Username
    "D"  => 0,           #Debug Level
    "m"  => 0            #email address
);

################################################################################
#                                                                              #
#                              main  MAIN                                      # 
#                                                                              #
################################################################################


my ($groupName, $errCode, $input);
my $ticketNum;

if (getopts('m:D:bc:d:f:g:p:t:Tu:y', \%options) != 1) {
    printUsage();
    exit(1);
}

$ticketNum = processOptions(\%account,\%options);

if ((checkExecMode(MODE_BATCH)) && 
    (verifyBatchOptions($account,\%options) != ERR_NONE))  {
    exit(ERR_INPUT);
}


if (!checkExistingCreds(KERB_CREDS_NEEDED) && checkExecMode(MODE_REAL)) {
    print "***\n";
    print "  * You do not currently posses the credentials needed *\n";
    print "  * Please 'kinit sysadmin' before trying to add users *\n";
    print "  * when not running this program in test mode.        *\n";
    print "***\n";

    exit(1);
} else {
    print "* Verified needed Kerberos Credentials\n\n";
}


if (!checkExecMode(MODE_BATCH)) {
    #interactively get the data we need

    #TODO: merge getTicketNumber, getInfo
    $ticketNum = getTicketNumber() unless $ticketNum;
   

    getInfo(\%account);

    ####  confirm the info before committing it  ####
    #if (!checkExecMode(MODE_ACCEPT)) {
    if (!checkExecMode(MODE_BATCH)) {
        do {
            $errCode = confirmInfo(\%account);
        } while (ERR_RETRY == $errCode);
        debugOutput("Information was confirmed.\n", DBL_DIAG);
    }
}

debugOutput("Making Account now.\n", DBL_DIAG);

$errCode = makeAccount(\%account);
if (ERR_NONE != $errCode) {
    print "Account Creation Failed. (makeAccount returned [$errCode])\n";
    exit(ERR_INTERNAL);
}


debugOutput("logging Account Info.\n", DBL_DIAG);
$errCode = logAccountCreation(\%account);
if (ERR_NONE != $errCode) {
    print "logAccount procedure failed.(logAccountCreation returned [$errCode])\n";
    exit(ERR_INTERNAL);
}


debugOutput("Verifying Account Info.\n", DBL_DIAG);
####  make sure we can find what we just committed  ####
verifyAccount(\%account);


#### account creation has succeeded. Update the ticket ####
if ($ticketNum > 0) {
    debugOutput("Outputting ticket update blurb.\n", DBL_DIAG);
    updateTicket(\%account,$ticketNum, DEFAULT_TICKET_NOTE_FILE);
}


#TODO: add a check to actually try to log in remotely
exit(ERR_NONE);




################################################################################
#                                                                              #
#                          SUBROUTINE DEFINITIONS                              #
#                                                                              #
################################################################################
sub debugOutput($$;)
{
    my ($msg, $level);

    $msg = shift;
    $level= shift;

    if (!$msg || !$level) {
        die "debugOutput: not passed needed arguments\n";
    }

    if ($debugLevel >= $level) {
        print "$msg";
    }
    return;
}

sub setExecMode($;)
{
    my $execFlag;

    debugOutput("*setExecMode(): [entry]\n", DBL_FT);
    $execFlag = shift;
    if (!$execFlag) { die "setExecMode: not passed needed arguments.\n"; }

    $execMode |= $execFlag;
    debugOutput("*setExecMode(): [$execMode]\n", DBL_FT);
    return $execMode;
}

sub clearExecMode($;)
{
    my $execFlag;

    debugOutput("*clearExecMode(): [entry]\n", DBL_FT);
    $execFlag = shift;
    if (!$execFlag) { die "clearExecMode: not passed needed arguments.\n"; }

    $execMode &= ~$execFlag;
    debugOutput("*clearExecMode(): [$execMode]\n", DBL_FT);

    return $execMode;
}

sub checkExecMode($;)
{
    my $execFlag;
    my $ret;

    debugOutput("*checkExecMode(): [entry]\n", DBL_FT);
    $execFlag = shift;
    if (!$execFlag) { die "checkExecMode: not passed needed arguments.\n"; }

    $ret = ($execMode & $execFlag ? 1 : 0);
    debugOutput("*checkExecMode(): [$ret]\n", DBL_FT);

    return $ret;
}
sub verifyBatchOptions($$;)
{
    my ($account, $options);
    my $ret;

    debugOutput("*verifyBatchOptions(): [entry]\n", DBL_FT);

    $account = shift;
    $options = shift;
    if (!$account || !$options) { die "verifyBatchOptions: not passed needed arguments\n"; }

    $ret = ERR_NONE;

    #### make sure all the required options for batch mode are given ####
    if (!$options->{u} || !$options->{f} || !$options->{d} || !$options->{g} || !$options->{c} || !$options->{d}) {
        print "Batch Mode execution requires: \n";
        print "    Username   (-u),\n";
        print "    Full Name  (-f),\n";
        print "    Department (-d),\n";
        print "    Group      (-g),\n";
        print "    CWID #     (-c)\n";
        print "    pipelineID (-p)\n";

        $ret = ERR_INPUT
    }

    debugOutput("*verifyBatchOptions(): [$ret]\n", DBL_FT);
    return $ret;
}

sub processOptions($$;)
{
    my ($account,$options);
    my ($userName,$firstName,$lastName,$cwid);
    my ($gid, %groupNameGid, %groupGidName);
    my $ticketNum;

    $account = shift;
    $options = shift;

    #TODO- implement debug output as bitwise OR so it isn't cumulative.
    #### set the debug output verbosity level ####
    $debugLevel = $options{D};

    debugOutput("*processOptions(): [entry]\n", DBL_FT);

    debugOutput("Debug Level is $debugLevel\n",DBL_DIAG);


    if (!$account || !$options) {
        die "processOptions: not passed needed arguments!\n";
    }
    debugOutput("*processOptions(): [entry]\n", DBL_FT);

    #### test mode passed in via Command Line Interface ####
    if ($options->{T} == 1) {
        print "***********************************************************\n";
        print "*  Running in Test Mode. No actual changes will be made   *\n";
        print "***********************************************************\n";
        clearExecMode(MODE_REAL);
    } elsif ($options->{T} == 0) {
        debugOutput("***********************************************************\n", DBL_DIAG);
        debugOutput("*  Running in Real Mode. Server data WILL be modified!!   *\n", DBL_DIAG);
        debugOutput("***********************************************************\n", DBL_DIAG);
        setExecMode(MODE_REAL);
    } else {
        print "Main: internal error in program logic detected. Option execMode:REAL is neither 1 nor 0!\n";
        exit(ERR_INTERNAL);
    }
    #### check if we're in batch mode or not ####
    if ($options->{b} == 0) {
        clearExecMode(MODE_BATCH);
        debugOutput("*************************************************************\n",  DBL_DIAG);
        debugOutput("*  Running in Interactive Mode. Will prompt for user input. *\n", DBL_DIAG);
        debugOutput("*************************************************************\n",  DBL_DIAG);
    } elsif ($options->{b} == 1) {
        setExecMode(MODE_BATCH);
        debugOutput("***********************************************************\n", DBL_DIAG);
        debugOutput("*  Running in Batch Mode. Will not prompt for input.      *\n", DBL_DIAG);
        debugOutput("***********************************************************\n", DBL_DIAG);

    }
    else {
        print "Main: internal error in program logic detected. Option execMode:BATCH is neither 1 nor 0!\n";
        exit(ERR_INTERNAL);
    }
        

    #### username passed in via CLI ####
    if ($options->{u}) {
        $userName = $options->{u};
        debugOutput("Assigning username from command-line option: [$options->{u}]\n", DBL_DIAG);
        #### will be verified against REGEX in-line with the interactive code to do the same ####
        $account->{ldapAccount}{uid} = $userName;
    }
    #### full name passed in via CLI ####
    if ($options->{f}) {
        ($firstName,$lastName) = split(/\s+/,$options->{f});
        debugOutput("Assigning full name from command-line option: [$options->{f}] [$firstName|$lastName]\n", DBL_DIAG);
        #### will be verified against REGEX in-line with the interactive code to do the same ####
        $account->{ldapAccount}{cn} = $firstName;
        $account->{ldapAccount}{sn} = $lastName;
    }

    #### Group name, or possibly a GID# passed in via CLI ####
    if ($options->{g}) {
        debugOutput("Assigning group from command-line option: [$options->{g}]\n", DBL_DIAG);
        #### will be verified against REGEX in-line with the interactive code to do the same ####
        $account->{ldapAccount}{gidNumber} = $options{g};
    }
    #### dept passed in via CLI ####
    if ($options->{d}) {
        debugOutput("Assigning department from command-line option: [$options->{d}]\n", DBL_DIAG);
        #### will be verified against REGEX in-line with the interactive code to do the same ####
        $account->{ldapAccount}{gecos} = $options->{d};
    }
    #### CWID passed in via CLI ####
    if ($options->{c}) {
        debugOutput("Assigning CWID from command-line option: [$options->{c}]\n", DBL_DIAG);
        #### will be verified against REGEX in-line with the interactive code to do the same ####
        $account->{ldapAccount}{cwid} = $options->{c};

        #### mark that this CWID info should be saved later ####
        $account->{ldapAccount}{cwid_status} = CWID_STAT_INPUT;
    }

    #TODO add a section for checking the pipelineID, as that will be required soon
    if ($options->{p} && $account->{ldapAccount}{cwid_status} != CWID_STAT_UNINIT) {
        debugOutput("Assigning pipeline ID from command-line option: [$options->{p}]\n", DBL_DIAG);
        #### will be verified against REGEX in-line with the interactive code to do the same ####
        $account->{ldapAccount}{pipelineID} = $options->{p};

        #### mark that this CWID info should be saved later ####
        $account->{ldapAccount}{cwid_status} = CWID_STAT_INPUT;
    }

    if ($options->{m}) {
        debugOutput("Assigning e-mail address from command-line option: [$options->{m}]", DBL_DIAG);
        $account->{ldapAccount}{mail} = $options->{m};
    }

    if ($options->{y}) {
        debugOutput("Mode set to Accept: all default values will be auto accepted", DBL_DIAG);
        setExecMode(MODE_ACCEPT);
    }

    if ($options->{t}) {
        debugOutput("Setting ticket number to [" . $options->{t} . "]\n", DBL_DIAG);
        $ticketNum = $options->{t};
    }

    debugOutput("*processOptions(): [void]\n", DBL_FT);
    return $ticketNum;
}

sub printUsage(;)
{
    debugOutput("*printUsage(): [entry]\n", DBL_FT);
    print "adduser [Tt] [-d <level>]\n";
    print "    Options:\n";
    print "        -b: batch mode, CAUTION!! DO NOT USE THIS OPTION YET!\n";
    print "        -c <CWID>: assign the CWID Number from the command line.\n";
    print "        -D <level>: debug mode, where <level> is an integer specifying the level of information to provide (0-2).\n";
    print "        -f \"<Full Name>\": assign the Full Name from the command line. UNTESTED!\n";
    print "        -g <groupIDNumber>: assign the Primary Group by GID number from the command line. UNTESTED!\n";
    print "        -d <department>: assign the Department Name as text from the command line. UNTESTED!\n";
    print "        -T: test mode. Do not actually change anything at the end, but get all the information.\n";
    print "        -t <ticket number>: update <ticket number> with the account creation info.\n";
    print "        -u <username>: assign the username from the command line. UNTESTED!\n";
    print "        -p <pipelineID>: assign the pipeline username from the command line. UNTESTED!\n";
    print "        -m <email address>: assign the e-mail address from the command line. UNTESTED!\n";
   
    debugOutput("*printUsage(): [void]\n", DBL_FT);
    return;
}

sub queryLdap($$$;)
{
    my ($account, $queryStr, $retStrRef);
    my $ldapResponse;
    my $errCode;

    debugOutput("*queryLdap(): [entry]\n", DBL_FT);

    $account = shift;
    $queryStr = shift;
    
    #### reference to scalar ####
    $retStrRef = shift;

    if (!$account || !$queryStr) { die "queryLdap: not passed needed arguments.\n"; }

    $errCode = ERR_NONE;
    $ldapResponse = `$ldapsearch -LLL $queryStr 2> /dev/null || echo "FAILURE"`;

    if ($ldapResponse =~ m/^FAILURE$/) {

        $errCode = ERR_SYSFAIL;
        print "queryLdap: Failed while querying ldapserver with: [$queryStr]\n;"
    }
    
    $$retStrRef = $ldapResponse;
    return $errCode;
}

sub queryKerberos($$$;)
{
    my ($account, $queryStr, $retStrRef);
    my ($kdcResponse, $kdcError);
    my $commandStr;
    my $errCode;


    debugOutput("*queryKerberos(): [entry]\n", DBL_FT);

    $account = shift;
    $queryStr = shift;
    $retStrRef = shift;

    if (!$account || !$queryStr || !$retStrRef) { die "queryKerberos: not passed needed arguments.\n"; }
 
    $errCode = ERR_NONE;

    ### XXX This is the reason some passwords will fail. There can't be double quotes here. ###
    $kdcResponse = `$kadmin -k -q "$queryStr" 2>/tmp/.addu.kadminError.$$ || echo "FAILURE"`;

    #$commandStr = "$kadmin -k -q $queryStr 2>/tmp/.addu.kadminError.$$";
    #$kdcResponse = `$commandStr || echo "FAILURE"`;

    $$retStrRef = $kdcResponse;

    #XXX- 106 is how long the usual auth output to stderr is. Longer than that means there is another line
    #TODO- find a better / more logical way to do this besides reading magical numbers
    if (-s "/tmp/.addu.kadminError.$$" > 106 && open(KADMIN_ERR, "<", "/tmp/.addu.kadminError.$$")) {

        $errCode = ERR_EXTERNAL;

        #XXX-get the second line 
        #TODO- do this logically as well
        
        #### read 1st line ####
        $kdcError = <KADMIN_ERR>;
        debugOutput("queryKerberos: Read line  [$kdcResponse] from error output.\n", DBL_ALG);

        #### read 2nd line ####
        $kdcError = <KADMIN_ERR>;
        debugOutput("queryKerberos: Read line  [$kdcResponse] from error output.\n", DBL_ALG);

        $$retStrRef = $kdcError;
    }
    debugOutput("queryKerberos: Stdout Response from KDC: [$kdcResponse]\n", DBL_ALG) if ($kdcResponse) ;
    debugOutput("queryKerberos: Stderr Response from KDC: [$kdcResponse]\n", DBL_ALG) if ($kdcResponse) ;

    if ($kdcResponse && $kdcResponse =~ qr/^FAILURE$/)  {
            $errCode = ERR_SYSFAIL;
            print "Failed while querying Kerberos.\n";
    }

    debugOutput("*queryKerberos(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub ldapLoginNameFree($;)
{
    my $userName;
    my $user;
    my @users; 

    $userName = shift;
    if (!$userName) { die "ldapLoginNameFree: not passed needed arguments!"; }

    debugOutput("*ldapLoginNameFree(): [entry]\n", DBL_FT);
    debugOutput("Querying LDAP for a list of user names\n", DBL_ALG);
    @users = `$ldapsearch -LLL -b dc=phy,dc=stevens-tech,dc=edu -h nirvana.phy '(objectClass=posixAccount)' uid 2>/dev/null| grep uid: | cut -d' ' -f2 || echo "FAILURE"`;

    if ($users[0] =~ qr/^FAILURE$/) {
        print "\n****Failed querying LDAP to get the current list of Accounts!****\n****\n";
    }
    foreach $user (@users) {
        chomp($user);
        if ($user eq $userName) {
            debugOutput("*ldapLoginNameFree(): [0]\n", DBL_FT);
            return 0;
        }
    }
    debugOutput("*ldapLoginNameFree(): [1]\n", DBL_FT);
    return 1;
}

sub ldapAutomountFree($;)
{
    my $userName;
    my $ldif;

    $userName = shift;
    if (!$userName) { die "ldapAutomountFree: not passed needed arguments!\n"; }

    debugOutput("*ldapAutomountFree(): [entry]\n", DBL_FT);
    debugOutput("Querying LDAP to check Automount.\n", DBL_ALG);
    $ldif = `$ldapsearch -LLL \\(\\&\\(objectClass=automount\\)\\(cn=$userName\\)\\) 2> /dev/null || echo "FAILURE"`;

    debugOutput("\nldapAutomountFree: debug: result: [$ldif]\n", DBL_ALG);

    if ($ldif =~ qr/^FAILURE$/) {
        print "\n****Failed querying LDAP to check for existing Automount entry!****\n****\n";
    } 
    elsif ($ldif =~ qr/^$/) {
        debugOutput("*ldapAutomountFree(): [1]\n", DBL_FT);
        return 1;    ####  it's free
    } else {
        debugOutput("*ldapAutomountFree(): [0]\n", DBL_FT);
        return 0;    #### returned data indicated an entry exists already
    }

}

sub verifyInputFormat($$;)
{
    my $inputStr;
    my $regex;

    $regex = shift;
    $inputStr = shift;

    if (!$regex || !$inputStr) { die "verifyInputFormat: Not passed needed arguments!"; }

    debugOutput("*verifyInputFormat(): [entry]\n", DBL_FT);
    if ($inputStr !~ qr/$regex/) {
        if (checkExecMode(MODE_BATCH)) {
            debugOutput("Batch Failure: Invalid Username specified. [$inputStr]\n", DBL_DIAG);
            exit(ERR_INPUT);
        } else {
            print "Unacceptable Input.\n";
            print "Usernames must start with a lower-case alphabetical";
            print " character and only contain alpha-numerical characters,";
            print " dashes and underscores.\n";
            print "LDAP UIDs must be above 999 and below 999999\n";
            debugOutput("*verifyInputFormat(): [ERR_RETRY]\n", DBL_FT);
            return ERR_RETRY;
        }
    }
    debugOutput("*verifyInputFormat(): [ERR_NONE]\n", DBL_FT);
    return ERR_NONE;
}

sub kerberosPrincipalFree($;)
{
    my $account;
    my ($kquery_str, $kresult);
    my $kadminExitCode;

    $account = shift;
    if (!$account) { die "kerberosPrincipalFree: not passed needed arguments!"; }

    debugOutput("*kerberosPrincipalFree(): [entry]\n", DBL_FT);
    $kquery_str = "get_principal $account->{krb5Princ}{principal}";

    debugOutput("Connecting to KDC to check for existing principal with name $account->{krb5Princ}{principal}\n", DBL_DIAG);
    #$kresult = `kadmin -k -q "$kquery_str" 2>/dev/null || echo "FAILURE"`;
    $kadminExitCode  = queryKerberos($account, $kquery_str, \$kresult);
    if ($kadminExitCode == ERR_EXTERNAL || $kadminExitCode == ERR_SYSFAIL) {

        ####  TODO- offline adds. Save until later styled  ####
        print "kerberosPrincipalFree: Failed to contact KDC.\n";

        ####  don't let it be used  ####
        debugOutput("*kerberosPrincipalFree(): [0]\n", DBL_FT);
        return 0;    

    } 
    elsif ($kresult =~ qr/^$/) {
        debugOutput("*kerberosPrincipalFree(): [1]\n", DBL_FT);
        return 1;    ####  free
    }
    elsif ($kresult =~ qr/Principal:.*/) {
        debugOutput("*kerberosPrincipalFree(): [0]\n", DBL_FT);
        return 0;    #### not free
    } 
    else {
        print "\nThis script needs an update.\nUnable to interpret response from KDC.\n";
        debugOutput("*kerberosPrincipalFree(): [0]\n", DBL_FT);
        return 0;
    }
}

sub zfsFree($;)
{
    my $zfsPath;
    my $zresult;

    $zfsPath = shift;
    if (!$zfsPath) { die "zfsFree: not passed needed arguments!"; }

    debugOutput("*zfsFree(): [entry]\n", DBL_FT);
    $zresult = `zfs list $zfsPath 2>/dev/null|| echo "FAILURE"`;

    if ($zresult =~ qr/^FAILURE$/) {
        debugOutput("*zfsFree(): [1]\n", DBL_FT);
        return 1;
    } elsif ($zresult =~ qr/^NAME.*MOUNTPOINT$/) {
        debugOutput("*zfsFree(): [0]\n", DBL_FT);
        return 0;
    }
}

sub printAccount($;)
{
    my $account;
    my ($key, $key2, $href);

    $account = shift;
    if (!$account) { die "printAccount: not passed needed arguments!\n"; }

    debugOutput("*printAccount(): [entry]\n", DBL_FT);

    foreach $key (keys(%$account)) {
        $href = $account->{$key};
        print "[$key]:\n";

        if($key =~ qr/^ldapAccount$|^ldapAutomount$|^krb5Princ$|^zfs$/) {
            foreach $key2 (keys(%$href)) {
                print "    $key2: [$account->{$key}{$key2}]\n";
            }
        }
    }

    debugOutput("*printAccount(): [void]\n", DBL_FT);
    return;
}

sub getLdapAccountComponent($;)
{
    my $account;
    my $ldif;
    my ($key, $key2, $href);
    my $ret;
    my $queryStr;

    $account =  shift;
    if (!$account) { die "getLdapAccountComponent: not passed needed arguments!\n"; }

    debugOutput("*getLdapAccountComponent(): [entry]\n", DBL_FT);
    debugOutput("Querying LDAP server to see if there is an account with username [$account->{ldapAccount}{uid}].\n", DBL_ALG);

    $queryStr = "\\(\\&\\(objectClass=posixAccount\\)\\(uid=$account->{ldapAccount}{uid}\\)\\)";
    $ret = queryLdap($account, $queryStr, \$ldif);

    if ($ret == ERR_SYSFAIL) {
        print "getLdapAccountComponent: Couldn't connect to LDAP server to get account information!\n";

    } elsif ($ldif =~ qr/^$/) {
        debugOutput("No LDAP account exists with that name yet.\n", DBL_DIAG);

        $account->{ldapAccount}{status} = STATUS_FREE;

    } else {

        debugOutput("An LDAP account with that name currently exists.\n", DBL_DIAG);

        ####  parse out the fields from the reply  ####
        $_ = $ldif;
        #### first name ####
        /cn: +([A-Za-z]*)/;
        $account->{ldapAccount}{cn} = $1;

        #### last name ####
        /sn: +([A-Za-z]*)/;
        $account->{ldapAccount}{sn} = $1;

        /uidNumber: +([0-9]*)/;
        $account->{ldapAccount}{uidNumber} = $1;

        /gidNumber: +([0-9]*)/;
        $account->{ldapAccount}{gidNumber} = $1;

        /homeDirectory: +(.*)/;
        $account->{ldapAccount}{homeDirectory} = $1;

        #### department ####
        /gecos: (.*)/;
        $account->{ldapAccount}{gecos} = $1;

        /loginShell: (.*)/;
        $account->{ldapAccount}{loginShell} = $1;

        /mail: (.*)/;
        $account->{ldapAccount}{mail} = $1;

        #### mark it in use ####
        $account->{ldapAccount}{status} = STATUS_INUSE;
        $ret = 1;
    }

    debugOutput("*getLdapAccountComponent(): [$ret]\n", DBL_FT);
    return $ret;
}

sub getLdapAutomountComponent($;)
{
    my $account;
    my $ldif;
    my $ret;
    my $queryStr;

    $account = shift;
    if (!$account) { die ": not passed needed arguments!\n"; }

    debugOutput("*getLdapAutomountComponent(): [entry]\n", DBL_FT);
    debugOutput("Querying LDAP Server to see if there is an automount entry for username [$account->{ldapAccount}{uid}].\n", DBL_ALG);

    $queryStr = "\\(\\&\\(objectClass=automount\\)\\(cn=$account->{ldapAccount}{uid}\\)\\)";
    $ret = queryLdap($account, $queryStr, \$ldif);

    if ($ret == ERR_SYSFAIL) { 
        print "Failed while querying LDAP server for automount information!";
    } 
    elsif ($ldif =~ qr/^$/) {
        debugOutput("No automount entry exists for an account with that name.\n", DBL_DIAG);
        $account->{ldapAutomount}{status} = STATUS_FREE;

    }
    else {
        debugOutput("An automount entry currently exists for that account.\n", DBL_DIAG);

        #### parse out the Automount stuff ####
        $_ = $ldif;
        m/automountInformation: (.*)(\n +(.*))?/;
        $account->{ldapAutomount}{automountInformation} = $1.$3;

        #### mark the automount component as in use ####
        $account->{ldapAutomount}{status} = STATUS_INUSE;
        $ret = 1;
    }

    debugOutput("*getLdapAutomountComponent(): [$ret]\n", DBL_FT);
    return $ret;
}

#TODO- this function needs some clean up.
# opaque references will make this hard to read later
sub getKerberosComponent($;)
{
    my $account;
    my ($kdcResponse, $kdcErr, $lineCount);
    my ($kadminQueryStr, $kdcRetCode);
    my $ret;

    $account = shift;
    if (!$account) { die "getKerberosComponent: not passed needed arguments!\n"; }
    
    debugOutput("*getKerberosComponent(): [entry]\n", DBL_FT);
    debugOutput("Querying Kerberos KDC to see if there is a principal named [$account->{ldapAccount}{uid}\@$account->{krb5Princ}{realm}].\n", DBL_ALG);

    $kadminQueryStr = "get_principal $account->{ldapAccount}{uid}";
    debugOutput("Kerberos  Query string: [$kadminQueryStr]\n", DBL_ALG);
    $kdcRetCode = queryKerberos($account, $kadminQueryStr, \$kdcResponse);

    if ($kdcResponse && $kdcResponse =~ qr/.*does not exist.*/) {
        debugOutput("No Kerberos Principal exists with that name.\n", DBL_DIAG);
        $account->{krb5Princ}{status} = STATUS_FREE;
        $ret = 0;

    }  
    else {
        debugOutput("A Kerberos Principal currently exists with that name.\n", DBL_DIAG);

        #### mark the kerberos component as in use ####
        $account->{krb5Princ}{status} = STATUS_INUSE;
        debugOutput("Kerberos component status: [$account->{krb5Princ}{status}]\n", DBL_ALG);

        ####  Parse out the data and put it into our internal Data Structure  ####
        $_ = $kdcResponse;
        m/Policy: (.*)/;
        $account->{krb5Princ}{policy} = $1;
        m/Principal:.*@(.*)/;
        $account->{krb5Princ}{realm} = $1;       
   
        debugOutput("Kerberos policy: [$account->{krb5Princ}{policy}]\n", DBL_ALG);
        debugOutput("Kerberos realm: [$account->{krb5Princ}{realm}]\n", DBL_ALG);
        debugOutput("Kerberos component status: [$account->{krb5Princ}{status}]\n", DBL_ALG);
 
        $ret = 1;
    }

    debugOutput("*getKerberosComponent(): [$ret]\n", DBL_FT);
    return $ret;
}

sub getZfsComponent($;)
{

    my $account;
    my $zfs;
    my $ret;

    $account = shift;
    if (!$account) { die "getZfsComponent: not passed needed arguments!\n"; }

    debugOutput("*getZfsComponent(): [entry]\n", DBL_FT);
    debugOutput("Checking current ZFS pool for [$account->{zfs}{zfsPath}]\n", DBL_ALG);

    #TODO- make one hook for all ZFS-system interaction
    $zfs = `zfs list "$account->{zfs}{zfsPath}" 2>/dev/null || echo "FAILURE"`;

    if ($zfs =~ qr/^FAILURE$/) {
        debugOutput("No ZFS exists for an account by that name.\n", DBL_DIAG);
        $account->{zfs}{status} = STATUS_FREE;
        $ret = 0;
    } 
    else {
        debugOutput("A ZFS currently exists for that account name.\n", DBL_DIAG);
        $account->{zfs}{status} = STATUS_INUSE;
        $ret = 1;

        #### Parse out the ZFS data ####
        #### Get the ZFS path first #### 
        $_ = $zfs;

        #TODO- this regex is not particularly identifiable.
        /([-0-9\/a-z]+) /;
        $account->{zfs}{zfsPath} = $1;

        #### now get the ZFS quota ####
        $zfs = `zfs get quota $account->{zfs}{zfsPath} || echo "FAILURE"`;
        if ($zfs =~ qr/^FAILURE$/) {
            print "getZfsComponent: failure while retrieving current quota information\n";
        } 
        else {
            $_=$zfs;
            /([1-9][0-9]*([Kk]|[Gg]|[Mm]|[Tt]))/;
            $account->{zfs}{quota} = $1;
        }
    }

    debugOutput("*getZfsComponent(): [$ret]\n", DBL_FT);
    return $ret;
}

sub getAccountComponent($$;)
{
    my ($account, $accountComponent);

    $account = shift;
    $accountComponent = shift;
    if (!$account || !$accountComponent) { die "getAccountComponent: not passed needed arguments!\n"; }

    debugOutput("*getAccountComponent(): [entry]\n", DBL_FT);
    $_ = $accountComponent;

    #### get the status of each component                                                        ####
    #### if the component exist, the information will be parsed out and assigned to the $account ####
    SWITCH: {
        if (m/^ldapAccount$/)    { getLdapAccountComponent($account);   last SWITCH; }
        if (m/^ldapAutomount$/)  { getLdapAutomountComponent($account); last SWITCH; }
        if (m/^krb5Princ$/)      { getKerberosComponent($account);      last SWITCH; }
        if (m/^zfs$/)            { getZfsComponent($account);           last SWITCH; }
    }

    debugOutput("*getAccountComponent(): [void]\n", DBL_FT);
    return;
}

sub getAccountStatus($;)
{
    my $account;
    my ($accountComponent,$initStatus, $curStatus);

    $account = shift;
    if (!$account) { die "accountStatus: Not passed needed arguments."; }

    debugOutput("*getAccountStatus(): [entry]\n", DBL_FT);

    ####  get the existing info for each of the account components  ####
    foreach $accountComponent (keys(%$account)) {
        #TODO-make this regex a defined constant at the top of the script so I can pass it around by name
        if ($accountComponent =~ qr/^ldapAccount$|^ldapAutomount$|^krb5Princ$|^zfs$/ ) { 
            
            getAccountComponent($account, $accountComponent);
       }
    }
        
    #### determine the state of the account. (Are all components or only some already present?) ####
    #### start with one.. why not .. oh, let's say ZFS. ####
    $initStatus = $account->{zfs}{status};
    foreach $accountComponent (keys(%$account)) {
        ####  if the current piece is not in the same state as the initial piece  ####
        ####  then we have an incomplete account                               ####

        #TODO-make this regex a defined constant at the top of the script so I can pass it around by name
        if ($accountComponent =~ qr/^ldapAccount$|^ldapAutomount$|^krb5Princ$/) {
            debugOutput("getAccountStatus: working with value [$accountComponent]\n", DBL_ALG);
            debugOutput("getAccountStatus: $accountComponent status: [$account->{$accountComponent}{status}]\n", DBL_ALG);

            $curStatus = $account->{$accountComponent}{status};
            if ($curStatus != $initStatus) {
                debugOutput("getAccountStatus: debug: [$accountComponent]($account->{$accountComponent}{status}) != [$initStatus]\n", DBL_ALG);

                $account->{status} = ACCNTSTAT_INCOMPLETE;
                last;
            }
        }
    }

    ####  If we havn't yet determined that it is incomplete, it is INUSE or FREE  ####
    if ($account->{status} == ACCNTSTAT_UNINIT) {

        ####  precondition: all account pieces have the same state:  ####
        ####      STATUS_FREE, or STATUS_INUSE                       ####

        if ($account->{ldapAccount}{status} == STATUS_FREE) {
                debugOutput("Username [$account->{ldapAccount}{uid}] is free to be used.\n", DBL_DIAG);
                $account->{status} = ACCNTSTAT_FREE;
        } else {
                print "!** Account already exists and is complete.\n";
                $account->{status} = ACCNTSTAT_COMPLETE;
        }
    }

    ####  value returned in $account->status  ####
    debugOutput("*getAccountStatus(): [$account->{status}]\n", DBL_FT);
    return;
}

sub printAccountStatus($;)
{
    
    my $account;
    my $accountPiece;

    $account = shift;

    if (!$account) { die "printAccountStatus: not passed needed arguments!\n"; }

    debugOutput("*printAccountStatus(): [entry]\n", DBL_FT);
    if ($account->{status} == ACCNTSTAT_INCOMPLETE) {
        print "********************************************************************************************************\n";
        print "*                                                                                                      *\n";
        print "*                                    Account in an Inconsistent State!                                 *\n";
        print "*        This means that while some parts of the account have been created, it is not yet functional   *\n";
        print "*        as not all the needed components exist! (Ldap Account + Automount, Kerberos principal, ZFS)   *\n";
        print "*        You can continue and create the missing parts or exit and start with a new account.           *\n";
        print "*        Continuing will fix the problem, so if you start over, make a note to fix this account later. *\n";
        print "*                                                                                                      *\n";
        print "********************************************************************************************************\n";
    }
    SWITCH: {
        if ($account->{status} == ACCNTSTAT_COMPLETE)   { print "\nAccount already exists.\n"; last SWITCH; }
        if ($account->{status} == ACCNTSTAT_INCOMPLETE) { print "\nAccount exists and is missing at least one needed component!\n"; last SWITCH; }
        if ($account->{status} == ACCNTSTAT_FREE)       { print "\nAccount components are free. Ready to create a new account.\n"; last SWITCH; }
    }
    if ($account->{status} != ACCNTSTAT_COMPLETE) {

        ####  loop through printing out which pieces are in use and which aren't  ####
        foreach $accountPiece (keys(%$account)) {
             if ($accountPiece =~ qr/^ldapAccount$|^ldapAutomount$|^krb5Princ$|^zfs$/ ) {
                SWITCH : {
                    if ($account->{$accountPiece}{status} == STATUS_FREE)  { print "Component [$accountPiece] hasn't yet been created.\n"; last SWITCH;}
                    if ($account->{$accountPiece}{status} == STATUS_INUSE) { print "Component [$accountPiece] exists already.\n"; last SWITCH; }
                }
            }
        }
    }
    
    debugOutput("*printAccountStatus(): [void]\n", DBL_FT);
    return;
}

sub getPipelineID($;)
{
    my $account;
    my ($cwid_fn, $cwid_ln, $cwid_filename, $output);
    my $errCode;
    my $ans;
    my $debugVar;

    debugOutput("*getPipelineID(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;
    $account = shift;
    die "getPipelineID: not passed needed arguments.\n" unless ($account);
 
    do {
        if (!checkExecMode(MODE_BATCH)) {
            if (checkExecMode(MODE_ACCEPT)) {
                debugOutput("getPipelineID: assigning pipeline id from ldap uid.\n", DBL_ALG);
                debugOutput("getPipelineID: uid: [$account->{ldapAccount}{uid}]\n", DBL_ALG);
                $account->{ldapAccount}{pipelineID} = $account->{ldapAccount}{uid};
            } else {
                print "Enter Campus Pipeline ID (\"off-campus\" for off-campus)";
                print "[$account->{ldapAccount}{uid}] ";
                chomp($account->{ldapAccount}{pipelineID} = <STDIN>);
                debugOutput("Saw [$account->{ldapAccount}{pipelineID}] as Campus Pipeline ID\n", DBL_ALG);
            }
        }
        ####  let them enter a blank line, just re-prompt  ####
        if ($account->{ldapAccount}{pipelineID} !~ qr/^$/ &&
            $account->{ldapAccount}{pipelineID} !~ m/^off-campus$/) {
            debugOutput("pipelineID did not match Null nor off-campus pattern.\n", DBL_ALG);

            $errCode = verifyInputFormat(USER_REGEX, $account->{ldapAccount}{pipelineID});
            if (ERR_RETRY == $errCode) {
                #if it didn't pass the regex test, we don't want to touch it for security.
                next;
            }

            #### note verifyInputFormat returns different error codes depending on
            #### checkExecMode(MODE_BATCH) return value.

            ####  we may be able to extract the First and Last Names from the  ####
            ####  existing CWID file we have.                                  ####

            #TODO grep only once here. This is inefficient / sloppy coding.
            $output = `grep -w "$account->{ldapAccount}{pipelineID}" "$CWID_FILENAME" || echo "FAILURE"`;
            debugOutput("Saw [$output] when searching CWID file.\n", DBL_ALG);

            if ($output !~ qr/^FAILURE$/) {
                debugOutput("Using CWID file for First and Last Names\n", DBL_DIAG);
                $output = `grep -w "$account->{ldapAccount}{pipelineID}" "$CWID_FILENAME" | awk -f $ADDUSER_FLNAMES_AWK_SCRIPT || echo "FAILURE"`;
            }
    
            ####  parse out the first and last name, splitting using whitespace  #####
            if ($output !~ qr/^FAILURE$/) {
                #well aren't we excessively explicit...
                $_ = $output;
                ($cwid_fn,$cwid_ln) = split;
    
                debugOutput("Assigning First and Last names grepped from CWID file.[$cwid_fn:$cwid_ln]\n", DBL_ALG);
                $account->{ldapAccount}{cn} = $cwid_fn;
                $account->{ldapAccount}{sn} = $cwid_ln;
                $account->{ldapAccount}{cwid_status} = CWID_STAT_FOUND;
            } else {
                debugOutput("This pipeline ID not found in CWID file.\n", DBL_ALG);
                ($cwid_fn, $cwid_ln) = ("", "");
                $account->{ldapAccount}{cwid_status} = CWID_STAT_NOTFOUND;
            }
        } elsif ($account->{ldapAccount}{pipelineID} =~ m/^off-campus$/) {
            debugOutput("Matched Regex for Campus Pipeline ID input.\n", DBL_ALG);
            print "Off Campus User? (Y/n): ";
            chomp($ans = <STDIN>);
            if ($ans =~ qr/[Yy]([Ee][Ss])?/ || $ans =~ qr/^$/) {
                $account->{ldapAccount}{pipelineID} = OFF_CAMPUS_PIPELINE_ID;
                debugOutput("Assigned default value for Pipeline ID\n", DBL_ALG);
                $account->{ldapAccount}{cwid} = CWID_OFF_CAMPUS;
                $account->{ldapAccount}{cwid_status} = CWID_STAT_NA;

            } else {
                $errCode = ERR_RETRY;
            }
        } elsif ($account->{ldapAccount}{pipelineID} =~ m/^$/) {
            $account->{ldapAccount}{pipelineID} = $account->{ldapAccount}{uid};
        }

    } while (ERR_RETRY == $errCode);

    debugOutput("*getPipelineID(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub getUserName($;)
{
    my $account;
    my ($cwid_fn, $cwid_ln, $cwid_filename, $output);
    my $errCode;

    $account = shift;
    if (!$account) { 
        die "getUserName: not passed needed arguments!";
     }
    debugOutput("*getUserName(): [entry]\n", DBL_FT);

    $errCode = ERR_RETRY;
    if ($account->{ldapAccount}{uid}) {
        $errCode = verifyInputFormat(USER_REGEX, $account->{ldapAccount}{uid})
    }

    do {
        if (!checkExecMode(MODE_BATCH) && ($errCode == ERR_RETRY)) {
            print "Enter SRCIT username: ";
            chomp($account->{ldapAccount}{uid} = <STDIN>);
        }

        ####  let them enter a blank line, just re-prompt  ####
        if ($account->{ldapAccount}{uid} !~ qr/^$/) {
            $errCode = verifyInputFormat(USER_REGEX, $account->{ldapAccount}{uid});

            #### note that verifyInputFormat returns different values depending on 
            #### whether or not the mode is MODE_BATCH

        } else {
            #### seed it w/ the default failure ####
            $errCode = ERR_RETRY;
        }
        if (ERR_NONE == $errCode) {
            ####  now assign all the username-based defaults we can                  ####
            ####  (overwritten in getAccountStatus() if the account already exists.) ####
    
            $account->{krb5Princ}{principal} = $account->{ldapAccount}{uid};
            $account->{zfs}{zfsPath} = ZHOME_BASE . "/" . $account->{ldapAccount}{uid};
         
        }   

    } while (ERR_RETRY == $errCode);

    debugOutput("*getUserName(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyName($;)
{
    my $name;
    my $ret;

    $name = shift;
    
    if (!$name) {
        die "verifyName: Not passed needed arguments.";
    }
    debugOutput("*verifyName(): [entry]\n", DBL_FT);
    
    if ($name !~ NAME_REGEX) { 
        print "Names must begin with an upper case letter and can be followed";
        print " only by lower-case letters, spaces, hyphens periods";
        print " and underscores\n";

        if (checkExecMode(MODE_BATCH)) {
            exit(ERR_INPUT);
        } else {
            $ret = ERR_RETRY;
        }
    } else {
        $ret = ERR_NONE;
    }

    debugOutput("*verifyName(): [$ret]\n", DBL_FT);
    return $ret;
}
    
#TODO: clean up this function. this just doesn't make much sense.
sub getFLNames($;)
{
    my $account;
    my ($fname, $lname);
    my $errCode;
   
    $account = shift;
    if (!$account) {
        die "getFLNames: not passed needed arguments!\n";
    }

    debugOutput("*getFLNames(): [entry]\n", DBL_FT);

    #### get the first name ####
    $errCode = ERR_NONE;
    do {
        ####  check if we found a default in getUserName()  ####
        if (checkExecMode(MODE_BATCH)) {
            #verifyBatchOptions makes sure this is non-empty

            $errCode = verifyInputFormat(NAME_REGEX, $account->{ldapAccount}{cn});

            #verifyInputMode will exit if it doesn't match and we're in batch mode

        } else {
            if ($account->{ldapAccount}{cn} =~ m/^.+$/) {
                if (checkExecMode(MODE_ACCEPT)) {
                    $fname = $account->{ldapAccount}{cn};
                } else {
                    print "Enter user's first name [$account->{ldapAccount}{cn}]: ";
                    chomp($fname = <STDIN>);
                }
            } else {
                print "Enter user's first name: ";
                chomp($fname = <STDIN>);
            }
        } 

        #TODO: what the hell is this if-stmt actually doing?
        if (checkExecMode(MODE_BATCH) || $fname =~ m/^.+$/) {
            #TODO: why not just use verifyInputFormat()?
            $errCode = verifyName($fname);

        } elsif ($fname =~ m/^$/ && $account->{ldapAccount}{cn} =~ m/^.+$/) {
            #TODO: isn't this taken care of above already? When would I hit this code??

            $fname = $account->{ldapAccount}{cn};
            $errCode = ERR_NONE;

        } else {
            $errCode = ERR_RETRY;
        }

    } while (ERR_RETRY == $errCode);

    #### get the last name ####
    $errCode = ERR_NONE;
    do { 
        if (checkExecMode(MODE_BATCH)) {
            $lname = $account->{ldapAccount}{sn};
        } else {
            if ($account->{ldapAccount}{sn} =~ m/^.+$/) {
                if (checkExecMode(MODE_ACCEPT) && $errCode != ERR_RETRY) {
                    $lname = $account->{ldapAccount}{sn};

                } else {
                    print "Enter user's last name [". $account->{ldapAccount}{sn} ."]: ";
                    chomp($lname = <STDIN>);
                }

            } else {
                print "Enter user's last name: ";
                chomp($lname = <STDIN>);
            }
        }

        if (checkExecMode(MODE_BATCH) || $lname =~ m/^.+$/) {
            $errCode = verifyName($lname);
        } elsif ($lname =~ m/^$/ && $account->{ldapAccount}{sn} =~ m/^.+$/) {
            $lname = $account->{ldapAccount}{sn};
            $errCode = ERR_NONE;
        } else {
            $errCode = ERR_RETRY;
        }
 
    } while (ERR_RETRY == $errCode);

    #### assign the names to the account structure ####
    #TODO: if we have these already, we assign above only to reassign here. Sloppy.
    if ($account->{ldapAccount}{cn} =~ m/^$/) {
       $account->{ldapAccount}{cn} = $fname;
    }

    #TODO: if we have these already, we assign above only to reassign here. Sloppy.
    if ($account->{ldapAccount}{sn} =~ m/^$/) {
        $account->{ldapAccount}{sn} = $lname;
    } 
    debugOutput("*getFLNames(): [($fname,$lname)]\n", DBL_FT);

    if (checkExecMode(MODE_BATCH) && $errCode != ERR_NONE) {
        #TODO: this is spaghetti code. Isn't this already taken care of?

        #### failure to verify name in batch mode exits in failure ####
        exit(ERR_INPUT);

    } else {
        return $errCode;
    }
}    

sub getZFSHome($;)
{

    my $account;
    my ($zhome, $default);

    debugOutput("*getZFSHome(): [entry]\n", DBL_FT);

    $account = shift;

    unless ($account) { die "getZFSHome: not passed needed arguments!"; }

    $default = $account->{zfs}{zfsPath};
    if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
        debugOutput("*getZFSHome(): [$account->{zfs}{zfsPath}]\n", DBL_FT);
        return;
    }

    do {
        print "ZFS Path to home directory [$default]: ";
        chomp($zhome = <STDIN>);
        if ($zhome =~ qr/^$/) {
            $zhome = $default; 
        }
        unless ($zhome =~ ZHOME_REGEX) { print "Sorry, illegal ZFS Path for home directory.\n" ; }
    } while ($zhome !~ ZHOME_REGEX);

    $account->{zfs}{zfsPath} = $zhome;
    debugOutput("*getZFSHome(): [void]\n", DBL_FT);
    return;
}

sub getPassword($;)
{
    my $account;
    my ($pw1, $pw2, $default_pw, $default_cwid, $cwid, $cwid_filename) ;
    my $pwLength;
    my $rejectString;

    debugOutput("*getPassword(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "getPassword: not passed needed arguments!\n"; }
    
    $default_cwid = "UNINIT";

    if (checkExecMode(MODE_BATCH)) {
        if ($account->{ldapAccount}{cwid} !~ m/$CWID_REGEX/) {
            debugOutput("*! Batch Failure: Invalid CWID passed in via Command Line\n", DBL_DIAG);
            exit(ERR_INPUT);
        } else {
            $cwid = $account->{ldapAccount}{cwid};
        }
    }

    do {
        if ($account->{ldapAccount}{pipelineID} !~ qr/^OFF_CAMPUS_PIPELINE_ID$/) {
            $default_cwid = `grep -w "$account->{ldapAccount}{pipelineID}" "$CWID_FILENAME" | awk -f $ADDUSER_CWID_AWK_SCRIPT || echo "Not Found"`;
            chomp($default_cwid);
            if ($default_cwid =~ qr/^Not Found$/) {
                debugOutput("No CWID found for $account->{ldapAccount}{pipelineID}\n", DBL_DIAG);
    
                #TODO: this is a bit messy as this is done again / already  in getFLNames.
                #Clean it up so this file searching is done all in one function
                $account->{ldapAccount}{cwid_status} = CWID_STAT_NOTFOUND;
            } else {
                $account->{ldapAccount}{cwid_status} = CWID_STAT_FOUND;
            }
        }

        if (!checkExecMode(MODE_BATCH)) {
            if (!$account->{ldapAccount}{cwid} || ($account->{ldapAccount}{cwid} 
                && $account->{ldapAccount}{cwid} !~ m/$CWID_REGEX/)) {

                if ($account->{ldapAccount}{cwid}) {
                    print "Invalid CWID: [$account->{ldapAccount}{cwid}]\n";
                }

                print "Enter Campus Wide ID Number [$default_cwid]: ";
                chomp($cwid = <STDIN>);
                $account->{ldapAccount}{cwid_status} = CWID_STAT_INPUT;

            } else { 
                $cwid = $account->{ldapAccount}{cwid};
            }
        }
        if ($cwid =~ qr/^$/) {
            debugOutput("Assigning Default CWID\n", DBL_DIAG);
            $cwid = $default_cwid;

        }

        debugOutput("CWID currently [$account->{ldapAccount}{cwid}]\n", DBL_ALG);
    } while ($cwid !~ m/$CWID_REGEX/);
    
    debugOutput("Accepted CWID\n", DBL_ALG);
    $account->{ldapAccount}{cwid} = $cwid;

    ####  set the length longer for admins  ####
    if ($account->{krb5Princ}{policy} eq "admin") {
        $pwLength = 14;

    } else {
        $pwLength = 10;
    }
        
    #TODO- make this string configurable at run-time / via command line option
    ####  the characters we refuse to accept into a password  ####
    #### no single, double or back quotes, no backslash ####
    $rejectString = qq('^"`\\);

    #$rejectString = "";

    do {
        $default_pw = generatePassword($pwLength, $rejectString);
        $default_pw .= $cwid;
        if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
            $pw2 = $pw1 = $default_pw;
        } else {
            print "Enter password (or 'R' to regenerate another) [$default_pw]: ";
            chomp($pw1 = <STDIN>);
            if ($pw1 !~ qr/^$/ && $pw1 !~ qr/^R$/) {
                print "Enter password again: ";
                chomp($pw2 = <STDIN>);
                if ($pw1 ne $pw2) {
                    print "Those didn't match. Please try again!\n";
                }
            }
            elsif ($pw1 =~ /^$/) {
                $pw1 = $pw2 = $default_pw;
            } 
        }
            
    } while ($pw1 =~ /^R$/ || $pw1 ne $pw2 || !validatePassword($pw1, $pwLength, $rejectString));

    $account->{krb5Princ}{password} = $pw1;
    debugOutput("*getPassword(): [void]\n", DBL_FT);
    return;
}

sub lookupKrb5Policies($;)
{
    my $account;
    my (@policies, $policy);
    my ($kdcQueryStr, $kdcRetCode, $kdcRetStr);

    debugOutput("*lookupKrb5Policies(): [entry]\n", DBL_FT);

    $account = shift;
    
    if (!$account) { die "lookupKrb5Policies: not passed needed arguments.\n"; }

    debugOutput("Looking up available Kerberos Policies.\n", DBL_ALG);
    #@policies = `kadmin -k -q list_policies 2>/dev/null || echo "FAILURE"`;
    
    $kdcQueryStr = "list_policies";
    $kdcRetCode = queryKerberos($account,qq($kdcQueryStr),\$kdcRetStr);

    if ($kdcRetCode == ERR_SYSFAIL || $kdcRetCode == ERR_EXTERNAL) {
        print "\n****Failed while querying KDC for available Kerberos Policies!****\n****\n";
    }

    debugOutput("lookupKrb5Policies: got [$kdcRetStr] back from queryKerberos()\n", DBL_ALG);
    @policies = split(/\s/, $kdcRetStr);
    ####  pretty them up. Munch away the trailing newline  ####
    foreach $policy (@policies) {
        chomp ($policy);
    }
    debugOutput("*lookupKrb5Policies(): [(@policies)]\n", DBL_FT);
    return (@policies); 
}

sub getKrb5Policy($;)
{
    my $account;
    my (@policies, $p, $policy, $defaultPolicy, %policyNumberName);
    my ($numPolicies, $n);
    my $errCode;

    debugOutput("*getKrb5Policy(): [entry]\n", DBL_FT);
    $account = shift;
    if (!$account) {
        die "getKrb5Policy: not passed needed arguments!";
    }

    @policies = lookupKrb5Policies($account);

    if (!checkExecMode(MODE_BATCH) && !checkExecMode(MODE_ACCEPT)) {
        print "The following Kerberos 5 Policies are available: \n";
    }

    $defaultPolicy = $account{krb5Princ}{policy};
    ####  print them out preceeded by a number and then save that number as a key  ####
    ####  into a hash table with the policy as the keyed value so they can select  ####
    ####  by the number, or by the name                                            ####
    $n = 0;
    foreach $p (@policies) {
        $n++;
        if (!checkExecMode(MODE_BATCH) && !checkExecMode(MODE_ACCEPT)) {
            print "$n) $p\n";
        }
        $policyNumberName{$n} = $p;
    } 
    $numPolicies = $n;

    ####  make sure we get a valid policy, either by number or by name  ####
    $errCode = ERR_RETRY;
    do {
        if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
            $policy = $defaultPolicy;
        } else {
            print "Enter Kerberos Policy to use for [$account->{ldapAccount}{uid}] (by Name or by Number) [$defaultPolicy]: ";
            chomp ($policy = <STDIN>);
        }

        if ($policy =~ qr/^[0-9]+$/) {
            if ($policy > $numPolicies || $policy <= 0) {
                if (!checkExecMode(MODE_BATCH)) {
                    print "Invalid Policy Number.\n";
                }
            } else {
                $policy = $policyNumberName{$policy};
                $errCode = ERR_NONE;
            }
        } elsif ($policy =~ qr/^$/) {
            $policy = $defaultPolicy;
            $errCode = ERR_NONE;
        } else {
            foreach $p (@policies) {
                $errCode = ERR_NONE if ($policy eq $p);
            }
            unless (ERR_NONE == $errCode) { print "$policy is not a valid policy\n"; }
        }               
    } while (ERR_RETRY == $errCode);

    $account->{krb5Princ}{policy} = $policy;
    debugOutput("*getKrb5Policy(): [void]\n", DBL_FT);
    return;
}

sub lookupLoginShells(;)
{
    my (@shells, $shell);

    debugOutput("*lookupLoginShells(): [entry]\n", DBL_FT);
    debugOutput("Getting a list of Login Shells for Driftwood 6.03\n", DBL_ALG);

    ####  Kludge. I copied the /etc/shells file from a driftwood machine  ####
    ####  and placed it here on deathstar in /etc.                        ####
    ####  TODO- make this dynamically retrieve a list of shells. LDAP?    ####

    @shells = `cat /etc/Driftwood6.03LoginShells || echo "FAILURE"`;
    
    if ($shells[0] =~ qr/^FAILURE$/) {
        print "\n****Failed to get a list of available shells!****\n****\n";
    }
    foreach $shell (@shells) {
        chomp ($shell);
    }
    debugOutput("*lookupLoginShells(): [(@shells)]\n", DBL_FT);
    return (@shells); 
}

sub getLoginShell($;)
{
    my $account;
    my $defaultShell;
    my $userName;
    my (@shells, $s, $shell, %shellNumberName);
    my ($numShells, $n);
    my $errcode;

    debugOutput("*getLoginShell(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) {
        die "getLoginShell: not passed needed arguments!";
    }
    
    
    @shells = lookupLoginShells();
    $userName = $account->{ldapAccount}{uid};
    $defaultShell = $account->{ldapAccount}{loginShell};
    if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
        return ERR_NONE;
    }

    print "The following Login Shells are available: \n";

    ####  see getKrb5Policy() for an explanation of this type of code  ####
    $n = 0;
    foreach $s (@shells) {
        $n++;
        print "$n) $s\n";
        $shellNumberName{$n} = $s;
    } 
    $numShells = $n;

    ####  make sure we get valid shell by name or by entry number  ####
    $errcode = ERR_RETRY;
    do {
        print "Enter Login Shell to use for [$userName] (by Name or by Number) [$defaultShell]: ";
        chomp ($shell = <STDIN>);
        if ($shell =~ qr/^[0-9]+$/) {
            if ($shell > $numShells || $shell <= 0) {
                print "Invalid Shell Number.\n";
            } else {
                $shell = $shellNumberName{$shell};
                $errcode = ERR_NONE;
            }
        } elsif ($shell =~ qr/^$/) {
            $errcode = ERR_NONE;
            $shell = $defaultShell;
        } else {
            foreach $s (@shells) {
                $errcode = ERR_NONE if ($shell eq $s);
            }
            unless ($errcode == ERR_NONE) { print "$shell is not a valid shell\n"; }
        }               
    } while (ERR_RETRY == $errcode);

    debugOutput("*getLoginShell(): [$shell]\n", DBL_FT);
    $account->{ldapAccount}{loginShell} = $shell;

    return $errCode;
}

sub getEmailAddress($;)
{
    my $account;
    my ($defaultAddress, $input);

    debugOutput("*getEmailAddress(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "getEmailAddress: not passed needed arguments."; }

    if ($account->{ldapAccount}{cwid} != CWID_OFF_CAMPUS) {
        $defaultAddress = $account->{ldapAccount}{uid} . '@stevens.edu';
    } else {
        $defaultAddress = "";
    }

    do {
        if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
            $input = $defaultAddress;
        } else {
            print "Enter email address [$defaultAddress]: ";
            chomp ($input = <STDIN>);
        }

        if ($input =~ qr/^$/) {
            debugOutput("Assigning email from default address\n", DBL_ALG);
            $account->{ldapAccount}{mail} = $defaultAddress;
        } elsif ($input) {
            $account->{ldapAccount}{mail} = $input;
        }
            
        #### check that it conforms to a valid e-mail address syntax ####
    } while ($account->{ldapAccount}{mail} !~ EMAIL_REGEX);

    if ($input) {
        $account->{ldapAccount}{mail} = $input;    
    } else {
        $account->{ldapAccount}{mail} = $defaultAddress;
    }

    debugOutput("*getEmailAddress(): [void]\n", DBL_FT);
    return;
}

####  check if the argument is free for use as a UID number  ####
sub ldapUIDFree($;)
{
    my $uidNumber;
    my $uid;
    my @uids; 
    
    $uidNumber = shift;
    if (!$uidNumber) { die "ldapUIDFree: not passed needed arguments!"; }

    debugOutput("*ldapUIDFree(): [entry]\n", DBL_FT);
    @uids = `$ldapsearch -LLL -b dc=phy,dc=stevens-tech,dc=edu -h nirvana.phy '(objectClass=posixAccount)' uidNumber 2>/dev/null| grep uidNumber: | cut -d' ' -f2 || echo "FAILURE"`;
    
    if ($uids[0] =~ qr/^FAILURE$/) {
        print "\n****\n****Failed while querying LDAP for a list of currently used UIDs!****\n****\n";
    }
    foreach $uid (@uids) {
        chomp($uid);
        if ($uid eq $uidNumber) {
            debugOutput("*ldapUIDFree(): [0]\n", DBL_FT);
            return 0;
        }
    }
    debugOutput("*ldapUIDFree(): [1]\n", DBL_FT);
    return 1;
}

sub verifyUidNumber($;)
{

    my $uid;
    my $errcode;

    $uid = shift;
    if (!$uid) { die "verifyUidNumber: Not passed needed arguments."; }

    debugOutput("*verifyUidNumber(): [entry]\n", DBL_FT);
    ####  check that it conforms to the regex defined  ####
    $errcode = verifyInputFormat(UID_REGEX, $uid);

    ####  make sure uid is not in use already  ####
    if ($errcode == ERR_NONE) {
        unless (ldapUIDFree($uid)) {
            print "Sorry LDAP UID [$uid] is already in use.\n";
            $errcode = ERR_RETRY;
        }
    }
    debugOutput("*verifyUidNumber(): [$errcode]\n", DBL_FT);
    return $errcode
}

sub lookupLdapUids(;)
{
    my ($uid, @uids);

    debugOutput("*lookupLdapUids(): [entry]\n", DBL_FT);
    ####  get all the Ldap UID numbers in a sorted list  ####
    @uids = `$ldapsearch -LLL '(objectClass=posixAccount)' uidNumber 2>/dev/null | grep uidNumber | cut -d: -f2 | sort -n || echo "FAILURE"`;

    if ($uids[0] =~ qr/^FAILURE$/) {
        print "\n****Failed while querying LDAP for a list of currently used UIDs!****\n****\n";
    }
    foreach $uid (@uids) {
        chomp($uid);
    }
    debugOutput("*lookupLdapUids(): [@uids]\n", DBL_FT);
    return @uids;
}

sub findFirstFreeUid($$)
{
    my ($min, $max);
    my (@uidsInUse, $prev, $next, $lowest, $i);

    $min = shift;
    $max = shift;
    if (!$min || !$max) { die "findFirstFreeUid: not passed needed arguments"; }

    debugOutput("*findFirstFreeUid(): [entry]\n", DBL_FT);
    ####  get a sorted list of numerical UIDs  ####
    @uidsInUse = lookupLdapUids();
 
    ####  Assumption: uidsInUse is already sorted                ####
    ####  get past the UIDs that are below the required minimum  ####
    $i = 0;
    while ($uidsInUse[$i] < $min) { 
        $i++; 
    }

    ####  find the first non-consecutive UID and return the first UID number  ####
    ####  that would be in this gap                                           ####

    $lowest = -1;
    $prev = $uidsInUse[$i];
    for (++$i; $i < @uidsInUse && $lowest == -1; $i++) {
        $next = $uidsInUse[$i];
        if ($next > ($prev + 1)) {
            $lowest = ($prev + 1);
        }
        $prev = $next;
    }
    if (-1 == $lowest) {
        if ( ($lowest = $uidsInUse[$i-1] + 1) > $max) {
            print "!*!*! Out of UIDs! *!*!*!\n";
            exit ERR_INTERNAL;
        }
    }
    debugOutput("*findFirstFreeUid(): [$lowest]\n", DBL_FT);
    return $lowest;
}

sub getUidNumber($;)
{
    my $account;
    my ($uid,$defaultUid);
    my $errcode;


    $account = shift;
    if (!$account) { die "getUidNumber: not passed needed arguments!\n"; }

    debugOutput("*getUidNumber(): [entry]\n", DBL_FT);
    ####  offer a suggested lowest unused UID number and verify the one that is entered    ####
    ####  is actually available to be used.                                                ####
    $defaultUid = findFirstFreeUid(UID_MIN, UID_MAX);
    if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
        debugOutput("*getUidNumber(): [$defaultUid]\n", DBL_FT);
        $account->{ldapAccount}{uidNumber} = $defaultUid;
        return;
    }

    do {
        print "Enter numerical UID [$defaultUid]: ";
        chomp($uid = <STDIN>);
   
        if ($uid) {
            $errcode = verifyUidNumber($uid);
        } else {
            $uid = $defaultUid;
            $errcode = ERR_NONE;
        }
    } while (ERR_RETRY == $errcode);

    debugOutput("*getUidNumber(): [$uid]\n", DBL_FT);
    $account->{ldapAccount}{uidNumber} = $uid;

    return;
}

sub lookupGids(;)
{
    my (@ldapGroupIds, $gid, $n, %ldapGroupGid, $groupName);
    
    debugOutput("*lookupGids(): [entry]\n", DBL_FT);
    debugOutput("Querying LDAP for a list of available Groups\n", DBL_ALG);
    @ldapGroupIds = `$ldapsearch -LLL '(objectClass=posixGroup)' gidNumber 2> /dev/null | grep gidNumber | cut -d' ' -f2 || echo "FAILURE"`;
    if ($ldapGroupIds[0] =~ qr/^FAILURE$/) {
        print "\n****Failure while querying LDAP server for available groups!****\n****\n";
    }

    ####  make a hash of Group Names => GID numbers  ####
    ####  (LDAP groups only)                         ####
    foreach $gid (@ldapGroupIds) {
        chomp($gid);
        if ( ($groupName = getgrgid($gid)) =~ m/^$/) {
            print "lookupGids: error getting a group name for GID [$gid]: $!\n";
            exit (ERR_SYSFAIL);
        }
        $ldapGroupGid{$groupName} = $gid;
    }
    endgrent();

    debugOutput("*lookupGids(): [@ldapGroupIds]\n", DBL_FT);
    return %ldapGroupGid;
}
    
####  make sure we get a valid group name, Group ID or diplayed entry number       ####
####  we can tell if it is an entry number or a GID by the range. All GIDs > 1000  ####
####  return the GID of the group entered                                          ####
sub verifyGroupSelection($$$$;)
{
    
    my ($input, $gidIndexName,$gidNameGid, $retGid);
    my %gidGidName;
    my ($gid, $groupName);
    my $errCode;

    debugOutput("*verifyGroupSelection(): [entry]\n", DBL_FT);

    $input = shift;
    $gidNameGid = shift;
    $gidIndexName = shift;
    $retGid = shift;
    
    if (!$input || !$gidNameGid || !$gidIndexName) { die "verifyGroupSelection: not passed needed arguments.\n"; }

    checkExecMode(MODE_BATCH) ? $errCode = ERR_INPUT : $errCode = ERR_RETRY;

    %gidGidName = reverse(%{$gidNameGid});
        
    if ($input =~ qr/^[0-9]+$/) {
        if ($input < 1000 && !$gidIndexName->{$input} && $input != 0) {
            $gid = -1;
            if (!checkExecMode(MODE_BATCH)) {
                print "Invalid Group Number.\n";
            }
        } elsif($input < 1000 && $gidIndexName->{$input}) {
            $groupName = $gidIndexName->{$input};
            $gid = $gidNameGid->{$groupName};
            $errCode = ERR_NONE;

        } elsif($input >= 1000 && $gidGidName{$input}) {
            $gid = $input;
            $errCode = ERR_NONE;
        }
    } else {
        foreach $groupName (keys(%{$gidNameGid})) {
            if ($input eq $groupName) {
                $gid = $gidNameGid->{$groupName};
                $errCode = ERR_NONE;
            }
        }
    }               

    if ($errCode != ERR_NONE) {
        if (checkExecMode(MODE_BATCH)) {
            debugOutput("*! Batch Failure: Invalid Group input passed in via Command Line. [$input]\n", DBL_DIAG);
            exit(ERR_INPUT);
        } else {
            print "\"$input\" is not a valid selection.\n"; 
        }
    }
    ####  return the GID that the entry matched in the argument supplied  ####
    $$retGid = $gid;

    debugOutput("*verifyGroupSelection(): [$errCode]\n", DBL_FT);
    return $errCode;
}

####  Takes: account hash ref, hash ref of LDAP groupName->Gid  ####
####  Returns: an array of GIDs  ####
sub getSupplementalGroups($$;)
{
    my ($account, $gidNameGid);
    my ($gid, $n, $g, %gidIndexName);
    my $input;
    my ($datum, @gids, @validGids);
    my $filler;

    #TODO- delineate the difference between errCode and error
    my ($errCode, $error);

    $account = shift;
    $gidNameGid = shift;
 
    if (!$account || !$gidNameGid) { die "getSupplementalGroups: not passed needed arguments.\n"; }

    debugOutput("*getSupplementalGroups(): [entry]\n", DBL_FT);

    ####  get all the supplemental groups in one line  ####
    $errCode = ERR_NONE;
    do {
        ####  print out the list of known groups  ####
        print "The following supplemental groups are available:\n";
        $n = 0;
        foreach $g (keys(%{$gidNameGid})) {
            if ( $gidNameGid->{$g} != $account->{ldapAccount}{gidNumber} ) {
                $n++;
                print "$n) $g\n";
                $gidIndexName{$n} = $g;
            }
        }
        ####  if this is not the first time through here, print out what we have  ####
        if (@validGids > 0) {
            print "You have already added the following groups: \n";
            foreach $datum (@validGids) {
                print "    $datum\n";
            }
        }
        ####  grab the input  ####
        print "Enter any supplemental groups (seperated by a space): ";
        chomp($input =  <STDIN>);

        if ($input =~ /^$/ ) {
            if (@validGids > 0) {
                debugOutput("Not adding any more supplemental groups.\n", DBL_DIAG);
            } else {
                debugOutput("Not adding any supplemental groups at all!\n", DBL_DIAG);
            }
            $errCode = ERR_NONE;  
        }

        ####  split input into a space-seperated list  ####
        @gids = split(/\s+/, $input);

        ####  verify each choice  ####
        foreach $datum (@gids) {

            #### TODO: make this function a variable argument function  ####
            $errCode = verifyGroupSelection($datum, $gidNameGid, \%gidIndexName, \$gid);

            if ($errCode != ERR_NONE) {
                ####  this selection couldn't be verified as valid  ####
                print "[$datum] is not a valid group selection.\n";
                $error = ERR_NOTFOUND;
                next;

            } else {
                #### append $gid to a list of valid gids  ####
                push @validGids, $gid
            }
        }

    } while (ERR_NOTFOUND == $error);
    
    debugOutput("*getSupplementalGroups(): [@validGids]\n", DBL_FT);
    return @validGids;
}

sub getGidNumber($;)
{
    my $account;
    my ($userName, $defaultGroup, $defaultGid);
    my (%gidGroupGid, $g, $gid, %gidIndexName, $groupName);
    my ($numGids, $n);
    my $input;
    my $errCode;

    $account = shift;
    if (!$account) { 
        die "getGidNumber: not passed needed arguments!";
    }
    debugOutput("*getGidNumber(): [entry]\n", DBL_FT);
    $userName = $account->{ldapAccount}{uid};

    ####  get a hash of GroupName => GroupNumber  ####
    ####  of all current LDAP groups              ####
    %gidGroupGid = lookupGids();

    $defaultGroup = "student";
    $defaultGid = getgrnam($defaultGroup);

    if (!checkExecMode(MODE_BATCH) && !checkExecMode(MODE_ACCEPT)) {
        print "The following Groups are available: \n";
    }

    ####  see getKrb5Princ() for explanation of this type of code  ####
    #TODO- put this type of code into a function. I use it a lot!
    $n = 0;
    foreach $g (keys(%gidGroupGid)) {
        $n++;
        if (!checkExecMode(MODE_BATCH) && !checkExecMode(MODE_ACCEPT)) {
            print "$n) $g\n";
        }
        $gidIndexName{$n} = $g;
    } 

    $errCode = ERR_RETRY;
    do {

        if (!checkExecMode(MODE_BATCH) && !checkExecMode(MODE_ACCEPT)) {
            print "Enter primary group to use for [$userName] (by Name or by Number) [$defaultGroup]: ";
            chomp ($input = <STDIN>);
        }  elsif (checkExecMode(MODE_BATCH)) {
            $input = $account->{ldapAccount}{gidNumber};
        } elsif (checkExecMode(MODE_ACCEPT)) {
            $input = $defaultGroup;
        }

        #### check for an empty input to accept the default  ####
        if ($input =~ qr/^$/) {
            debugOutput("getGidNumber(): applying default Group\n", DBL_ALG);
            $errCode = ERR_NONE;
            $gid = $defaultGid;    
        } else {
            ####  verify what was selected  ####
            debugOutput("getGidNumber(): verifying Group Selection\n", DBL_ALG);

            #### the GID will be returned in $gid  ####
            #### exit Hook for batch mode in verifyGroupSelection() ####
            $errCode = verifyGroupSelection($input,\%gidGroupGid,\%gidIndexName,\$gid);
        }

    } while (ERR_RETRY == $errCode);

    $account->{ldapAccount}{gidNumber} = $gid;
    debugOutput("getGidNumber(): assigned primary GID: [$account->{ldapAccount}{gidNumber}]\n", DBL_ALG);
    #getSupplementalGroups($account, \%gidGroupGid);
    #TODO- call external supplemental groups program / module to add user to the selected groups

    debugOutput("*getGidNumber(): [void]\n", DBL_FT);

    return;

}

sub getDepartment($;)
{
    my $account;
    my ($dept, $d, @depts, $numDepts, %deptNumberName, $defaultDept, $input, $n);
    my $errCode;

    debugOutput("*getDepartment(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "getDepartment: not passed needed arguments!\n"; }

    @depts = ("Chemistry Chemical Biology and Biomedical Engineering",
              "Chemical Engineering Material Science",
              "Civil Environmental and Ocean Engineering",
              "Computer Science",
              "Electrical and Computer Engineering",
              "Mathematical Sciences",
              "Mechanical Engineering",
              "Physics and Engineering Physics",
              "School of Technology Management",
              "School of Systems and Enterprises",
              "Academic Administration",
              "College of Arts and Letters"
             );

    $n = 0;
    foreach $d (sort(@depts)) {
        if (!checkExecMode(MODE_BATCH) && !checkExecMode(MODE_ACCEPT)) {
            $n++;
            print "$n) $d\n";
        }
        $deptNumberName{$n} = $d;
    }
    $numDepts = $n;

    $defaultDept = "Computer Science";

    #### default to failure ####
    if (checkExecMode(MODE_BATCH)) {
        $errCode = ERR_INPUT;
    } else { 
        $errCode = ERR_RETRY;
    }
    
    do {
        if (!checkExecMode(MODE_BATCH) && !$account->{ldapAccount}{gecos}) {
            if (!checkExecMode(MODE_ACCEPT)) {
              print "Enter Dept by Name or Number [$defaultDept]: ";
              chomp($input = <STDIN>);
            } else {
                $input = $defaultDept;
            }
        }
            
        #### batch mode already has the input in the account structure ####
        if (checkExecMode(MODE_BATCH)) {
            $input = $account->{ldapAccount}{gecos};
        } 

        if ($input =~ qr/^[0-9]+$/) {
            if ($input > $numDepts || $input <= 0) {
                if (!checkExecMode(MODE_BATCH)) {
                    print "Invalid Dept Number.\n";
                } else {
                    $errCode = ERR_INPUT;
                }
            } else {
                $dept = $deptNumberName{$input};
                $errCode = ERR_NONE;
            }
        } elsif ($input =~ qr/^$/) {
        
            #### user entered a new line to accept default ####
            $dept = $defaultDept;
            $errCode = ERR_NONE;
        } else {  
            #### department was entered by name ####
            foreach $d (@depts) {
                if ($input eq $d) {
                    $errCode = ERR_NONE;
                    $dept = $input;
                }
            }

            if (!checkExecMode(MODE_BATCH)) { 
                if (ERR_NONE != $errCode) {
                    print "$input is not a valid department\n"; 
                }
            }
        }               
    } while (ERR_RETRY == $errCode);

    if (checkExecMode(MODE_BATCH) && ERR_INPUT == $errCode) {
        debugOutput("*! Batch Failure: Invalid Department input passed in via Command Line. [$input]\n", DBL_DIAG);
        exit(ERR_INPUT);
    } 
    
    debugOutput("Assigning name, department in gecos data: [$dept]\n", DBL_DIAG);
    $account->{ldapAccount}{gecos} = "$account{ldapAccount}{cn} $account{ldapAccount}{sn}, $dept";
    debugOutput("*getDepartment(): [void]\n", DBL_FT);
    
    return;
}

sub getGecos($;)
{

    my $account;
    my $gecos;
    
    $account = shift;
    if (!$account) {
        die "getGecos: not passed needed arguments!";
    }
    debugOutput("*getGecos(): [entry]\n", DBL_FT);

    print "Enter GECOS data: ";
    chomp($gecos = <STDIN>);
    debugOutput("*getGecos(): $account->{ldapAccount}{cn},]\n", DBL_FT);
    return "$account->{ldapAccount}{cn}, $account->{ldapAccount}{sn}, $gecos";
}

sub getZfsQuota($;)
{
    my $account;
    my ($input,$defaultQuota, $quotaStr);
    my $errCode;
   
    debugOutput("*getZfsQuota(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) {
        die "getZfsQuota: not passed needed arguments!\n";
    }
    
    ####  figure out default quota based on group ID  ####
    if ($account->{ldapAccount}{gidNumber} == getgrnam("professor")) {
        $defaultQuota = "10G";
    } 
    elsif ($account->{ldapAccount}{gidNumber} == getgrnam("srcit")) {
        $defaultQuota = "7G";
    }
    else {
        $defaultQuota = "1G";
    }
    do {
        if (checkExecMode(MODE_BATCH) || checkExecMode(MODE_ACCEPT)) {
            $input = $account->{zfs}{quota} = $defaultQuota;
        } else {
            print "Enter quota for user [$defaultQuota]: ";
            chomp($input = <STDIN>);
        }
        if ($input !~ QUOTA_REGEX && $input !~ qr/^$/) {
            if (checkExecMode(MODE_BATCH)) {
                debugOutput("Batch Failure: Invalid quota expression. Must be a number followed by one letter K,M,G, or T\n", DBL_DIAG);
                exit(ERR_INPUT);
            }
            print "Not a valid quota expression. Must be a number followed by one letter for Kilobytes(K), Megs(M), Gigs(G), or Terabytes(T)\n";
             
        } elsif ($input =~ qr/^$/) {
            $quotaStr = $defaultQuota;
        } else {
            $quotaStr = $input;
        }
    } while ( $input !~ QUOTA_REGEX && $input !~ qr/^$/);

    $account->{zfs}{quota} = $quotaStr;
    debugOutput("*getZfsQuota(): [void]\n", DBL_FT);
    return;
}

sub checkSubStatus($$;)
{
    my ($account, $accountKey);

    $account = shift;
    $accountKey = shift;

    if (!$account) { die ": not passed needed arguments!\n"; }
    
    debugOutput("*checkSubStatus(): [entry]\n", DBL_FT);
    if ($account->{$accountKey}{status} == STATUS_INUSE) {
        debugOutput("$accountKey part of account already exists. Skipping.\n", DBL_DIAG);
    }
    elsif ($account->{$accountKey}{status} == STATUS_UNINIT) {
        print "checkSubStatus: Fix me. I just saw an uninitialized value that I never should.\n";
        print "Account Key: [$accountKey].\n";
        print "Value: [$account->{$accountKey}{status}]\n";
        print "Exiting before things get worse.\n";
        exit(ERR_INTERNAL);
    } 
    else {
        print "checkSubStatus: Fix me. I just saw an unknown value ($accountKey: $account->{$accountKey}{status})that I never should.\n";
        print " Exiting before things get worse.\n";
        exit(ERR_INTERNAL);
    }

    debugOutput("*checkSubStatus(): [void]\n", DBL_FT);
    return;
}
sub getLdapInfo($;)
{
    my $account;
    my $loginShell;

    $account = shift;
    if (!$account) { 
        die "getLdapInfo: not passed needed arguments!\n"; 
    }
    debugOutput("*getLdapInfo(): [entry]\n", DBL_FT);
        
    if ($account->{ldapAccount}{status} == STATUS_FREE) {
        getFLNames($account);
        getDepartment($account);
        getGidNumber($account);
        getEmailAddress($account);
        getUidNumber($account);
        getLoginShell($account);
        $account->{ldapAccount}{homeDirectory} = "/home/$account->{ldapAccount}{uid}";

    } 
    else {
        checkSubStatus($account, "ldapAccount");
    }
    debugOutput("*getLdapInfo(): [void]\n", DBL_FT);
    return;
}

sub getKerberosInfo($;)
{
    my $account;
    my $policy;

    debugOutput("*getKerberosInfo(): [entry]\n", DBL_FT);
    $account = shift;
    if (!$account) { 
        die "getKerberosInfo: not passed needed arguments!\n"; 
    }
    
    if ($account->{krb5Princ}{status} == STATUS_FREE) {
        getKrb5Policy($account);
        getPassword($account);
    } else {
        checkSubStatus($account, "krb5Princ"); 
    }
    debugOutput("*getKerberosInfo(): [void]\n", DBL_FT);
    return;
}

sub getZfsInfo($;)
{

    my $account;

    $account = shift;
    if (!$account) { 
        die "getZfsInfo: not passed needed arguments!\n"; 
    }
    debugOutput("*getZfsInfo(): [entry]\n", DBL_FT);

    if ($account->{zfs}{status} == STATUS_FREE) {
        getZFSHome($account);
        getZfsQuota($account);
    } else {
        checkSubStatus($account, "zfs");
    }

    debugOutput("*getZfsInfo(): [void]\n", DBL_FT);
    return;
}

sub checkAccountStatus($;)
{

    my $account;
    my ($input,$errCode);

    $account = shift;
    if (!$account) { 
        die "checkAccountStatus: not passed needed arguments!\n"; 
    }
    debugOutput("*checkAccountStatus(): [entry]\n", DBL_FT);
    
    $errCode = ERR_NONE;

    getAccountStatus($account);

    if (checkExecMode(MODE_BATCH) && $account->{status} != ACCNTSTAT_FREE) {
        #### batching is only allowed on clean accounts for now ####

        #TODO- add a batch repair / force option that plows through incomplete accounts
        # even when in batch mode
        debugOutput("*! This account has existing parts and you've requested Batch Mode creation.\n", DBL_DIAG);
        debugOutput("*! Right now, I'll only batch create accounts that don't exist at all.\n", DBL_DIAG);
        debugOutput("*! Please use this tool in interactive mode to clean up incomplete accounts.\n", DBL_DIAG);

        #### let the calling program know if the account is complete or partial ####
        $account->{status} == ACCNTSTAT_INCOMPLETE ? exit ERR_INPUT : exit ERR_INUSE;
    }

    if ($account->{status} == ACCNTSTAT_COMPLETE) {
        $errCode = ERR_INUSE;
    }
    elsif (!checkExecMode(MODE_BATCH) && $account->{status} == ACCNTSTAT_INCOMPLETE) {

        #TODO- allow modifying existing information here
        printAccountStatus($account);
        do {
            print "Would you like to continue? (Y/n): ";
            chomp($input = <STDIN>);
            if ($input =~ qr/[Yy]([Ee][Ss])?/ || $input =~ qr/^$/) {
                ;
        
            } elsif ($input =~ qr/[Nn]([Oo])?/) {
               print "*!- Exiting having made no changes to anything. Bye.\n";
               exit ERR_RETRY;
            } else {
               $errCode = ERR_RETRY;
            }
        } while ($errCode == ERR_RETRY);
    }

    debugOutput("*checkAccountStatus(): [void]\n", DBL_FT);
    return $errCode;
}
sub getInfo($;)
{
    my $account;
    my $errCode;
     
    $account = shift;
    if (!$account) {
        die "getInfo: not passed needed arguments!\n";
    }
    debugOutput("*getInfo(): [entry]\n", DBL_FT);

    #### may already have it from command line ####
    getUserName($account);

    if ( ($errCode = checkAccountStatus($account)) == ERR_INUSE) {
        print "*This account already exists with all the required components. (ZFS, Kerberos, Ldap Account, Ldap Automount)\n";
        print "*Nothing else to do for this account with user name \"$account->{ldapAccount}{uid}\!\"\n";
        exit(ERR_INUSE);
    }

    getPipelineID($account);

    #### batch mode checks done before each prompt ####
    if (STATUS_FREE == $account->{ldapAccount}{status}) {
        getLdapInfo($account);
    }

    if (STATUS_FREE == $account->{krb5Princ}{status}) {
        getKerberosInfo($account);
    }

    if (STATUS_FREE == $account->{zfs}{status}) {
        getZfsInfo($account);
    }

    debugOutput("*getInfo(): [void]\n", DBL_FT);
    return $errCode;
}
sub changeInfo($;)
{
    my $dataToChange;
    my ($fileName, $forkPid, $errCode, $changedInfo);

    $dataToChange = shift;
    $fileName = "/tmp/.srcit_adduDS.$$";
    if (!defined($dataToChange)) {
        die "changeInfo: not passed needed arguments!";
    }
    debugOutput("*changeInfo(): [entry]\n", DBL_FT);

    debugOutput("*changeInfo(): [ERR_SYSFAIL]\n", DBL_FT);
    open(TMP_FILE, ">$fileName") || return ERR_SYSFAIL;
    print TMP_FILE "$$dataToChange";
    close(TMP_FILE);

    ####  re-open it for reading  ####
    debugOutput("*changeInfo(): [ERR_SYSFAIL]\n", DBL_FT);
    open(TMP_FILE, "<$fileName") || return ERR_SYSFAIL;

    if (!defined($forkPid = fork())) {
        print "Can't fork a process to edit the data with vi. You'll have to change it with another tool later.\n";
        $errCode = ERR_SYSFAIL;

    } elsif ($forkPid > 0) {
        ####  parent process  ####
        waitpid($forkPid, 0);
        ####  child process is now finished  ####
        chomp($changedInfo = <TMP_FILE>);
        $errCode = ERR_NONE;

    } elsif ($forkPid == 0) {
        ####  child process  ####
        exec("/opt/csw/bin/vim $fileName") || print "Can't find vim on this system. You'll have to change this data later with a different tool.";
        $errCode = ERR_SYSFAIL;
        exit(ERR_SYSFAIL);
    }

    $$dataToChange = $changedInfo;    
    print "\nChanged to $$dataToChange\n";
    debugOutput("*changeInfo(): [$errCode]\n", DBL_FT);
    return $errCode;
}
sub confirmInfo($;)
{

    my ($input, $n);
    my ($groupName, %indexData, $errCode, $infoToChange, $fref); 
    my $account;


    $account = shift;
    if (!$account) {
        die "confirmInfo: not passed needed arguments\n";
    }
    debugOutput("*confirmInfo(): [entry]\n", DBL_FT);

    ####  tell the user what information we're going to use  ####
    ####  TODO- Can I put this in a loop somehow? This is ugly  ####
    $n=0;
    print "\nConfirm the following information is correct before continuing\n";
    print ++$n . ") User Name: \"$account->{ldapAccount}{uid}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{uid};
    print ++$n . ") First Name: \"$account->{ldapAccount}{cn}\" \n";
    $indexData{$n} = \$account->{ldapAccount}{cn};
    print ++$n . ") Last Name: \"$account->{ldapAccount}{sn}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{sn};
    print ++$n . ") E-mail Address: \"$account->{ldapAccount}{mail}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{mail};
    print ++$n . ") Gecos Info: \"$account->{ldapAccount}{gecos}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{gecos};
    print ++$n . ") Numerical UID: \"$account->{ldapAccount}{uidNumber}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{uidNumber};
    $groupName = getgrgid($account->{ldapAccount}{gidNumber});
    print ++$n . ") Group: $groupName ($account->{ldapAccount}{gidNumber})\n";
    $indexData{$n} = \$account->{ldapAccount}{gidNumber};
    print ++$n . ") Automounted Home Directory: \"$account->{ldapAccount}{homeDirectory}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{homeDirectory};
    print ++$n . ") Login shell: \"$account->{ldapAccount}{loginShell}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{loginShell};

    print ++$n . ") Password: \"$account->{krb5Princ}{password}\"\n";
    $indexData{$n} = \$account->{krb5Princ}{password};
    print ++$n . ") Kerberos 5 Policy: \"$account->{krb5Princ}{policy}\"\n";
    $indexData{$n} = \$account->{krb5Princ}{policy};

    print ++$n . ") ZFS Home Path: \"$account->{zfs}{zfsPath}\"\n";
    $indexData{$n} = \$account->{zfs}{zfsPath};
    print ++$n . ") ZFS Quota: \"$account->{zfs}{quota}\"\n";
    $indexData{$n} = \$account->{zfs}{quota};

    print ++$n . ") Campus Pipeline ID: \"$account->{ldapAccount}{pipelineID}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{pipelineID};
    print ++$n . ") Campus Wide ID Number: \"$account->{ldapAccount}{cwid}\"\n";
    $indexData{$n} = \$account->{ldapAccount}{cwid};
    

    print "\n\nIs this information correct? (Y/n): ";
    chomp($input = <STDIN>);
    if ($input =~ qr/[Yy]([Ee][Ss])?/ || $input =~ qr/^$/) {
        $errCode = ERR_NONE;

    } elsif ($input =~ qr/[Nn]([Oo])?/) {
        do {
            print "Which would you like to change? (select by number): ";
            chomp($input =  <STDIN>);
        } while ($input =~ m/^$/ || $input !~ m/^[0-9]+$/ || $input < 1 || $input > $n);

        $infoToChange = $indexData{$input};
        print "Changing $input: $$infoToChange\n";
        if ( ($errCode = changeInfo($infoToChange)) == ERR_SYSFAIL) {
            print "System Error while changing input. You'll have to do it later another way.\n";
        }
        $indexData{$input} = $$infoToChange;
        $errCode = ERR_RETRY;
    } else {
        $errCode = ERR_RETRY;
    }
    debugOutput("*confirmInfo(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub createAccountLdif($;)
{

    my $account;
    my $accountFileName;

    $account = shift;
    if (!$account) {
        die "createAccountLdif: not passed needed arguments.";
    }
    debugOutput("*createAccountLdif(): [entry]\n", DBL_FT);
    $accountFileName = "/root/ldap/ldif/ou/users/" . $account->{ldapAccount}{uid} . ".ldif";

    if (checkExecMode(MODE_REAL)) {
        debugOutput("Creating account LDIF in /root/ldap/ldif/ou/users\n", DBL_DIAG);

        open(LDIF_FH, ">", $accountFileName) || die "Couldn't create file named [$accountFileName].\n";

        #TODO: there is a library to manipualte LDIFs I believe.
        print LDIF_FH "dn: uid=$account->{ldapAccount}{uid},ou=users,dc=phy,dc=stevens-tech,dc=edu\n";
        print LDIF_FH "objectClass: top\n";
        print LDIF_FH "objectClass: posixAccount\n";
        print LDIF_FH "objectClass: shadowAccount\n";
        print LDIF_FH "objectClass: inetOrgPerson\n";
        print LDIF_FH "uid: $account->{ldapAccount}{uid}\n";
        print LDIF_FH "cn: $account->{ldapAccount}{cn}\n";
        print LDIF_FH "sn: $account->{ldapAccount}{sn}\n";
        print LDIF_FH "mail: $account->{ldapAccount}{mail}\n";
        print LDIF_FH "uidNumber: $account->{ldapAccount}{uidNumber}\n";
        print LDIF_FH "gidNumber: $account->{ldapAccount}{gidNumber}\n";
        print LDIF_FH "homeDirectory: /home/$account->{ldapAccount}{uid}\n";
        print LDIF_FH "loginShell: $account->{ldapAccount}{loginShell}\n";
        print LDIF_FH "gecos: $account->{ldapAccount}{gecos}\n";

        close(LDIF_FH);
    } elsif (!checkExecMode(MODE_REAL)) { 
        debugOutput("Running in Test Mode. Skipping creation of local LDAP Account LDIF file.\n", DBL_DIAG);

    } else {
        print "createAccountLdif: internal error in program logic detected. execMode:1 is neither TEST nor REAL\n";
        $errCode = ERR_INTERNAL;
    }
    
    debugOutput("*createAccountLdif(): [$accountFileName]\n", DBL_FT);
    return $accountFileName;
}
sub createAutomountLdif($;)
{
    my $account;
    my $automountFileName;

    $account = shift;
    if (!$account) {
         die "createAutomountLdif: not passed needed arguments!";
    }
    debugOutput("*createAutomountLdif(): [entry]\n", DBL_FT);

    $automountFileName = $automountLdifDir . $account->{ldapAccount}{uid} . ".ldif";

    if (checkExecMode(MODE_REAL)) {
        debugOutput("Creating Automount LDIF in /root/ldap/ldif/ou/automount\n", DBL_DIAG);
        open(LDIF_FH, ">", $automountFileName) || die "Couldn't create file named [$automountFileName]\n";

        print LDIF_FH "dn: cn=$account->{ldapAccount}{uid},ou=auto.home,dc=phy,dc=stevens-tech,dc=edu\n";
        print LDIF_FH "objectClass: automount\n";
        #print LDIF_FH "automountInformation: -rw,rsize=32768,wsize=32768,sync,intr,vers=3,quota deathstar.phy.stevens-tech.edu:/export/home/$account->{ldapAccount}{uid}\n";
        # modifying this to work with vader, not deathstar
        # Jan 10, 2012 jlight
        print LDIF_FH "automountInformation: -rw,rsize=32768,wsize=32768,sync,intr,vers=3,quota vader.srcit.stevens-tech.edu:/export/home/$account->{ldapAccount}{uid}\n";
        
        print LDIF_FH "cn: $account->{ldapAccount}{uid}\n";
        close(LDIF_FH);
    }
    elsif (!checkExecMode(MODE_REAL)) {
        debugOutput("Running in Test Mode. Skipping creation of local LDAP Automount LDIF file.\n", DBL_DIAG);
    }
    else {
        print "createAutomountLdif: internal error in program logic detected. execMode:1 is neither TEST nor REAL\n";
        $errCode = ERR_INTERNAL;
    }
    
    debugOutput("*createAutomountLdif(): [$automountFileName]\n", DBL_FT);
    return $automountFileName;
}

sub getMode($;)
{
    my $mode;

    $mode = shift;

    debugOutput("*getMode(): [$mode]\n", DBL_FT);
    return $mode; 
}

sub addUserAccountToLdap($;)
{
    my $account;
    my $accountFileName;
    my $errCode;

    debugOutput("*addUserAccountToLdap(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "addUserAccountToLdap: not passed needed arguments!\n"; }
    $errCode = ERR_NONE;

    $accountFileName = createAccountLdif($account);

    if (!checkExecMode(MODE_REAL)) {
        debugOutput("Running in Test Mode. Skipping the call to add the account to the LDAP tree\n", DBL_DIAG);
    } else {
        if (STATUS_FREE == $account->{ldapAccount}{status}){
            debugOutput("Adding account to LDAP DIT\n", DBL_DIAG);

            #TODO: don't call external programs. Breaks portability + is inefficient
            if (system("$ldapadd -f $accountFileName >/dev/null 2>/dev/null") > 0) {
                print STDERR "\n****\n****FAILED to add Account Information!!!****\n****\n";

                if (checkExecMode(MODE_BATCH)) {
                    exit(ERR_SYSFAIL);
                } else {
                    $errCode = ERR_SYSFAIL;
                }
            } else {
                debugOutput("- Successfully added account to LDAP tree.\n", DBL_DIAG);
            }

        } elsif (STATUS_INUSE == $account->{ldapAccount}{status}) {
            debugOutput("Ldap account already exists. Skipping adding account to LDAP.\n", DBL_DIAG);

        } else {
            print STDERR "addUserAccountToLdap: internal error in program logic detected.\n";
            print STDERR "    LdapAccount component's status is neither INUSE nor FREE!\n";
            $errCode = ERR_INTERNAL;
        }
    }
    debugOutput("*addUserAccountToLdap(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub addUserAutomountToLdap($;)
{
    my $account;
    my $automountFileName;
    my $errCode;

    $account = shift;
    if (!$account) { die "addUserAutomountToLdap: not passed needed arguments!\n"; }
    debugOutput("*addUserAutomountToLdap(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;

    $automountFileName = createAutomountLdif($account);

    if (checkExecMode(MODE_REAL)) {
        if (STATUS_FREE == $account->{ldapAutomount}{status}) {
            debugOutput("Adding new Automount Entry.\n", DBL_DIAG);
            if (system ("$ldapadd -f $automountFileName > /dev/null 2>/dev/null") > 0) {
                print "\n****\n****FAILED to add Automount Information!!!****\n****\n";
                if (checkExecMode(MODE_BATCH)) {
                    exit(ERR_SYSFAIL);
                } else {
                    $errCode = ERR_SYSFAIL;
                }
            } else {
                debugOutput("- Successfully added automount information to LDAP.\n", DBL_DIAG);
            }     
        } elsif (STATUS_INUSE == $account->{ldapAutomount}{status}) {
            debugOutput("Automount already exists, skipping adding automount.\n", DBL_DIAG);
        } else {
            print STDERR "addUserAutomountToLdap: internal error in program logic detected.\n";
            print STDERR "    Automount component's status is neither INUSE nor FREE yet!\n";
            $errCode = ERR_INTERNAL;
        }
    }

    debugOutput("*addUserAutomountToLdap(): [$errCode]\n", DBL_FT);
    return $errCode;
}
    
sub addUserToLdap($;)
{
    my ($account, $accountFileName, $automountFileName);
    my $errCode;

    $account = shift;
    if (!$account) {
        die "addUserToLdap: Missing needed arguments.";
    }
    debugOutput("*addUserToLdap(): [entry]\n", DBL_FT);
    $errCode = ERR_NONE;

    $errCode = addUserAccountToLdap($account);

    #TODO- find a graceful way to return multiple errors
    $errCode = addUserAutomountToLdap($account);

    debugOutput("*addUserToLdap(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub addPrincipalToKerberos($;)
{
    my $account;
    my ($kdcRetCode, $kadminQueryStr, $kdcRetStr);
    my $errCode;

    debugOutput("*addPrincipalToKerberos(): [entry]\n", DBL_FT);

    $account = shift;
    $errCode = ERR_NONE;
    if (!$account) {
        print STDERR "addPrincipalToKerberos: not passed needed arguments!\n";
        exit(ERR_INTERNAL);
    }


    ####  Create Kerberos Principal, set password  ####
    #TODO: use the kadmin library to do this.
    $kadminQueryStr = qq(ank +needchange -policy $account->{krb5Princ}{policy} -pw $account->{krb5Princ}{password} $account->{ldapAccount}{uid});
    

    if ($account->{krb5Princ}{status} == STATUS_INUSE) {
    }
  
    if (checkExecMode(MODE_REAL)) {
        if ($account->{krb5Princ}{status} == STATUS_FREE) {
            debugOutput("Creating new Kerberos Principal...\n", DBL_DIAG);
            $kdcRetCode = queryKerberos($account, qq($kadminQueryStr), \$kdcRetStr);
            if ($kdcRetCode == ERR_SYSFAIL || $kdcRetCode == ERR_EXTERNAL) {
                print "****\n****Failed while adding new principal to KDC!****\n****\n";
                $errCode = ERR_SYSFAIL;
                if (checkExecMode(MODE_BATCH)) {
                    exit(ERR_SYSFAIL);
                }
            }
        } elsif ($account->{krb5Princ}{status} == STATUS_INUSE) {
            ####  TODO- put code to modify existing principal here  ####
            debugOutput("Skipping adding already existing Kerberos Info to KDC.\n", DBL_DIAG);
            print STDERR "Modifying existing Kerberos information isn't yet supported\n";
            $errCode = ERR_UNIMPLEMENTED;
        } else {
            print "addPrincipalToKerberos: Problem in program's internal logic detected. Kerberos Component not marked as INUSE nor FREE yet!\n";
            $errCode = ERR_INTERNAL;
        }
    } else {
        debugOutput("Running in Test Mode. Skipping the call to add principal to Kerberos KDC.\n", DBL_DIAG);
    }

    debugOutput("*addPrincipalToKerberos(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub createZfs($;)
{
    my $account;
    my $zfs;
    my $errCode;

    $account = shift;
    if (!$account) {
        die "createZfs: not passed needed arguments!\n";
    }
    debugOutput("*createZfs(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;

    if (checkExecMode(MODE_REAL)) {
        if ($account->{zfs}{status} == STATUS_FREE) {
            debugOutput("Creating ZFS quota:[$account{zfs}{quota}] path:[$account->{zfs}{zfsPath}]\n", DBL_DIAG); 
            print "Creating ZFS. This may take a moment.\n";
            if (system("zfs create -o quota=$account->{zfs}{quota} $account->{zfs}{zfsPath}") > 0) {
                print "\n****\n****Failed while creating new ZFS!****\n****\n";
                if (checkExecMode(MODE_BATCH)) {
                    exit(ERR_SYSFAIL);
                }
                $errCode = ERR_SYSFAIL;
            }
            debugOutput("Copying /etc/skel/.[lb]* to new ZFS home directory\n", DBL_DIAG);

            #TODO: doesn't perl have its own 'cp' command? Don't spawn a shell for this.
            if (system("cp  /etc/skel/.[lb]* /export/home/$account->{ldapAccount}{uid}") > 0) {
                print "\n****\n****Failed while copying /etc/skel to new ZFS!****\n****\n";
                $errCode = ERR_SYSFAIL;
                if (checkExecMode(MODE_BATCH)) {
                    exit(ERR_SYSFAIL);
                }
            }
            debugOutput("Chowning files just copied.\n", DBL_DIAG);
            if (system("chown -R $account->{ldapAccount}{uidNumber}:$account->{ldapAccount}{gidNumber} /export/home/$account->{ldapAccount}{uid}") > 0) {
                print "\n****\n****Failed while chowning home to user! ****\n****\n";
                if (checkExecMode(MODE_BATCH)) {
                    exit(ERR_SYSFAIL);
                }
                $errCode = ERR_SYSFAIL;
            }
        } elsif ($account->{zfs}{status} == STATUS_INUSE) {
            #TODO: review this functionality of modifying existing info. When does it make sense to do so?

            ####  Can't change the path, so only quota is left to change.  ####
            debugOutput("Changing quota to [$account->{zfs}{quota}] for $account->{ldapAccount}{uid}.\n", DBL_DIAG);
            $zfs = `zfs set quota=$account->{zfs}{quota} $account->{zfs}{zfsPath}|| echo FAILURE`;
            if ($zfs eq "FAILURE") {
                print STDERR "createZfs: unable to modify quota for $account->{ldapAccount}{uid}!\n";
            }
        } else {
            print "createZfs: internal error in program logic detected. ZFS component not marked as INUSE, nor as FREE yet!";
            $errCode = ERR_INTERNAL;
        }
    } else {
        debugOutput("Running in Test Mode. Skipping the call to create new ZFS.\n", DBL_DIAG);
    }

    debugOutput("*createZfs(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub addToDoorAccessQueue($;)
{
    
    my $account;
    my $fileName = $DAQ_FILENAME;
    my $errCode;

    debugOutput("*addToDoorAccessQueue(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "addToDoorAccessQueue: not passed needed arguments!\n"; }

    $errCode = ERR_NONE;
    open(DAQ_FILE, ">>", "$fileName") or print "Error opening the Door Access File ($DAQ_FILENAME): $!\n", return ERR_SYSFAIL;
    
    if ($account->{status} == STATUS_FREE && checkExecMode(MODE_REAL)) {
        print "Adding username [$account->{ldapAccount}{uid}] to Door Access Queue.\n";
        print DAQ_FILE "$account->{ldapAccount}{uid}\n";
    } else {
        if ($account->{status} != STATUS_FREE) {
            print "Not adding non-free username [$account->{ldapAccount}{uid}] to Door Access Queue.\n";
        }
        if (!checkExecMode(MODE_REAL)) {
            print "Running in Test Mode. Skipping adding user [$account->{ldapAccount}{uid}] to Door Access Queue.\n";
        }
    }

    close(DAQ_FILE);

    debugOutput("*addToDoorAccessQueue(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub addToEmailQueue($;)
{
    my $account;
    my $emailFH;
    my $errCode;


    debugOutput("*addToEmailQueue(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "addToEmailQueue: not passed needed arguments.\n"; }

    #TODO- move opening of all files to a seperate function?
    open($emailFH,">>",$EMAIL_QUEUE_FILE) or print "addToEmailQueue: can't open E-mail Queue file ($EMAIL_QUEUE_FILE): $!", return ERR_SYSFAIL;

    #### log the username and initial password to e-mail to them ####
    #TODO- work out a secure way to do this. (encrypt e-mail with user's public key.)

    if (checkExecMode(MODE_REAL)) {
        if (ACCNTSTAT_FREE == $account->{status}) {
            print $emailFH "$account->{ldapAccount}{uid}:$account->{krb5Princ}{password}\n";
            $errCode = ERR_NONE;
        }
        else {
            $errCode = ERR_INUSE; 
        }
    } else {
        print "Running in Test Mode. Skipping adding of username/pw to E-mail Queue file.\n";
        $errCode = ERR_NONE;
    }

    debugOutput("*addToEmailQueue(): [$errCode]\n", DBL_FT);
    return $errCode
}
    
sub verifyLdapAccount($;)
{
    my $account;
    my @output;
    my $errCode;


    $account = shift;
    if (!$account) { 
        die "verifyLdapAccount: not passed needed arguments!\n";
    }
    debugOutput("*verifyLdapAccount(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;

    if (checkExecMode(MODE_REAL)) {
        #TODO: don't spawn a shell. Use the perl LDAP libs
        @output = `$ldapsearch -LLL \\(\\&\\(objectClass=posixAccount\\)\\(uid=$account->{ldapAccount}{uid}\\)\\) uid 2>/dev/null | grep uid: | cut -d: -f2 || echo "FAILURE"`;

        if (@output == 0) {
            print "\n!!! Can't verify that this account actually exists in the LDAP Tree...\n";
            print "Please check it with 'ldapsearch', and if needed add it with 'ldapadd -f'.\n";
            print "The LDIF file you need is in ~/ldap/ldif/ou/users\n";
            print "Look for <accountName>.ldif\n";
            $errCode = ERR_NOTFOUND;
        } elsif ($output[0] =~ qr/^FAILURE$/) {
            print "\n****\n**** Failed while querying LDAP server about new account information! ****\n****\n";
            $errCode = ERR_SYSFAIL;
        } 
    } 
    elsif (!checkExecMode(MODE_REAL)) {
        debugOutput("Running in Test Mode. Skipping verification of LDAP Account\n", DBL_DIAG);
    }
    else {

        print "verifyLdapAccount: internal error in program logic detected. execMode:1 is neither TEST nor REAL\n";
        $errCode = ERR_INTERNAL;
    }
    debugOutput("*verifyLdapAccount(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyAutomount($;)
{
    my $account;
    my @output;
    my $errCode;


    $account = shift;
    if (!$account) { 
        die "verifyAutomount: not passed needed arguments!\n";
    }
    debugOutput("*verifyAutomount(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;

    if (checkExecMode(MODE_REAL)) {
        #TODO: don't spawn a shell. Use the perl LDAP libs
        @output = `$ldapsearch -LLL \\(\\&\\(objectClass=automount\\)\\(cn=$account->{ldapAccount}{uid}\\)\\) automountInformation 2>/dev/null | grep automountInformation: | cut -d: -f2 || echo "FAILURE"`;

        if (@output == 0) {
            print "\n!!! Can't verify that this account's automount entry actually exists in the LDAP Tree...\n";
            print "Please check it with 'ldapsearch', and if needed add it with 'ldapadd -f'.\n";
            print "The LDIF file you need is in ~/ldap/ldif/ou/automount\n";
            print "Look for <accountName>.ldif\n";
            $errCode = ERR_NOTFOUND;
        }elsif ($output[0] =~ qr/^FAILURE$/) {
            print "\n****\n**** Failed while querying LDAP server about new account's automount information! ****\n****\n";
            $errCode = ERR_SYSFAIL;
        }
    }
    elsif (!checkExecMode(MODE_REAL)) {
        debugOutput("Running in Test Mode. Skipping verification of Automount info.\n", DBL_DIAG);
    }
    else {
        print "verifyAutomount: internal error in program logic detected. execMode:1 is neither TEST nor REAL\n";
        $errCode = ERR_INTERNAL;
    }

    debugOutput("*verifyAutomount(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyKrb5Princ($;)
{ 
    my $account;
    my (@output,$kadmin_query_str);
    my $errCode;


    $account = shift;
    if (!$account) { 
        die "verifyKrb5Princ: not passed needed arguments!\n";
    }
    debugOutput("*verifyKrb5Princ(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;

    $kadmin_query_str = "get_principal $account->{ldapAccount}{uid}";

    if (checkExecMode(MODE_REAL)) {
        #TODO: don't spawn a shell. Use the perl kadmin lib
        @output = `kadmin -k -q "$kadmin_query_str" 2>/dev/null || echo "FAILURE"`;

        if (@output == 0) {
            print "\n!!! Can't verify that this account's Kerberos Principal actually exists in the Kerberos Database.\n";
            print "Please check it with 'kadmin', and if needed add it with 'add_principal'.\n";
            $errCode = ERR_NOTFOUND;
        } elsif ($output[0] =~ qr/^FAILURE$/) {
            print "\n****\n**** Failed while querying LDAP server about new account's automount information! ****\n****\n";
            $errCode = ERR_SYSFAIL;
        }
    }
    elsif (!checkExecMode(MODE_REAL)) {
        debugOutput("Running in Test Mode. Skipping verification of Kerberos info.\n", DBL_DIAG);
    }
    else {
        print "verifyKrb5Princ: internal error in program logic detected. execMode:1 is neither TEST nor REAL\n";
        $errCode = ERR_INTERNAL;
    }

    debugOutput("*verifyKrb5Princ(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyZfs($;)
{
    my $account;
    my (@output,$kadmin_query_str);
    my $errCode;


    $account = shift;
    if (!$account) { 
        die "verifyZfs: not passed needed arguments!\n";
    }
    debugOutput("*verifyZfs(): [entry]\n", DBL_FT);

    $errCode = ERR_NONE;

    if (checkExecMode(MODE_REAL)) {
        @output = `zfs list $account->{zfs}{zfsPath} 2> /dev/null || echo "FAILURE"`;

        if (@output == 0 || $output[0] =~ qr/^FAILURE$/) {
            print "\n!!! Can't verify that this account's ZFS actually exists in the ZPool.\n";
            print "Please check it with 'zfs list', and if needed add it with 'zfs create'.\n";
            $errCode = ERR_NOTFOUND;
        } 
    }
    elsif (!checkExecMode(MODE_REAL)) {
        debugOutput("Running in Test Mode. Skipping verification of ZFS info.\n", DBL_DIAG);
    }
    else {
        print "verifyZfs: internal error in program logic detected. execMode:1 is neither TEST nor REAL\n";
        $errCode = ERR_INTERNAL;
    }
    debugOutput("*verifyZfs(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyDoorAccessQueue($;)
{
    my $account;
    my (@output, $lineNumber,$daqFileName);
    my $errCode;

    $account = shift;
    if (!$account) { die "verifyDoorAccessQueue: not passed needed arguments!\n"; }
    
    $daqFileName = $DAQ_FILENAME;

    $errCode = ERR_NONE;
    if (checkExecMode(MODE_REAL)) {
        $lineNumber = `/usr/xpg4/bin/grep -n $account->{ldapAccount}{uid} $daqFileName | cut -d':' -f1 || echo "FAILURE"`;
        if ( $lineNumber =~ /^FAILURE$/ ) {
            $errCode = ERR_NOTFOUND;
            print "\nCan't verify that account has been queued in the Door Access Request List.\n";
            print "Please add the username ($account->{ldapAccount}{uid}) manually to the Door Access file $DAQ_FILENAME.\n";
        } else {
            if (!checkExecMode(MODE_BATCH)) {
                print "Username \"$account->{ldapAccount}{uid}\" is in the door access queue file at line $lineNumber\n";
            }
        }
    } else {
        print "Running in Test Mode. Skipping verification of Door Access Queue file.\n";
    }
         
    return $errCode;
}

sub verifyEmailQueue($;)
{
    my $account;
    my $errCode;
    my $lineNum;

    debugOutput("*verifyEmailQueue() [entry]\n", DBL_FT);
    $account = shift;

    if (!$account) { die "verifyEmailAccessQueue: not passed needed arguments.\n"; }

    if (checkExecMode(MODE_REAL)) {
        $lineNum = `/usr/xpg4/bin/grep -wn $account->{ldapAccount}{uid} $EMAIL_QUEUE_FILE | cut -d':' -f1 || echo "FAILURE"`;
        if ($lineNum =~ m/^FAILURE$/) {
            print "Can't verify that username [$account->{ldapAccount}{uid}] is in the E-mail Queue file($EMAIL_QUEUE_FILE)\n";
            print "You should manually change this user's password and send them an e-mail with the new password.\n";
            $errCode =  ERR_INTERNAL;
        } else {
            print "Username [$account->{ldapAccount}{uid}] is in the E-mail at line [$lineNum]\n";
            $errCode = ERR_NONE;
        }
    } else { 
        print "Running in Test Mode. Skipping verification of Email Queue file.\n";
        $errCode = ERR_NONE;
    }

    debugOutput("*verifyEmailQueue() [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyCwidDb($;)
{
    my $account;
    my $lineNum;
    my $errCode;

    debugOutput("*verifyCwidDb(): [entry]\n", DBL_FT);
    $account = shift;
    if (!$account) {
       die "verifyCwidDb: not passed needed arguments!\n";
    }

    if (checkExecMode(MODE_REAL)) {
        $lineNum = `/usr/xpg4/bin/grep -wn "$account->{ldapAccount}{uid}" "$CWID_FILENAME" | cut -d':' -f1 || echo "FAILURE"`;
        if ($lineNum =~ m/^FAILURE$/) {
            print "Can't verify that username [$account->{ldapAccount}{uid}] is in the CWID DB file($CWID_FILENAME)\n";
            $errCode =  ERR_INTERNAL;
        } else {
            print "Username [$account->{ldapAccount}{uid}] is in the CWID DB at line [$lineNum]\n";
            $errCode = ERR_NONE;
        }
    } else { 
        print "Running in Test Mode. Skipping verification of CWID DB.\n";
        $errCode = ERR_NONE;
    }
    debugOutput("*verifyCwidDb(): [$errCode]\n", DBL_FT);
    return $errCode;
}

sub verifyAccount($;)
{
    my $account;
    my (@errCode,$err);
 
    debugOutput("*verifyAccount(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) {
        die "verifyAccount: not passed needed arguments!\n";
    }
    
    #TODO-this is not a bright way of doing this
    $errCode[0] = verifyLdapAccount($account);
    $errCode[1] = verifyAutomount($account);
    $errCode[2] = verifyKrb5Princ($account);
    $errCode[3] = verifyZfs($account);
    $errCode[4] = verifyDoorAccessQueue($account);
    $errCode[5] = verifyEmailQueue($account);
    $errCode[6] = verifyCwidDb($account);

    #XXX - inherently broken code below.
    foreach $err (@errCode) {
        if (ERR_NONE != $err) {
            #TODO - this should be able to handle each error
            #right here somehow.
            $errCode[0] = $err;
        }
    }

    debugOutput("*verifyAccount(): [$errCode[0]]\n", DBL_FT);
    return $errCode[0];
}


#TODO: seperate out the things that add the user's name to the logs / access
#queues from this function as they are not really part of 'making' the account
#but are more specifically an epilogue that occurs AFTEr this function
sub makeAccount($;) 
{
    my $account;
    my $input;
    my $errCode;

    $account = shift;

    if (!$account) {
        die "makeAccount: not passed needed arguments!\n";
    } 
    debugOutput("*makeAccount(): [entry]\n", DBL_FT);

    if ( ($errCode = addUserToLdap($account)) != ERR_NONE) {
        print STDERR "Error while adding account to LDAP Tree.\n";
        if (!checkExecMode(MODE_BATCH)) {
            print "Continue to add Kerberos Information and create ZFS anyway? (y/N): ";
            $input = <STDIN>;
            if ($input =~ qr/[Nn]([Oo])?/ || $input =~ qr/^$/) {
                print "Ldif files are in LDAP_DIR/users and LDAP_DIR/automount as $account->{ldapAccount}{uid}.ldif\n";
                print "Exiting...\n";
                exit(-1);
            }
        }
    }

    if ( ($errCode = addPrincipalToKerberos($account)) != ERR_NONE) {
        print STDERR "Error while adding principal to KDC.\n";
        if (!checkExecMode(MODE_BATCH)) {
            print "Continue to Create ZFS Anyway? (y/N): ";
            $input = <STDIN>;
            if ($input =~ qr/[Nn]([Oo])?/ || $input =~ qr/^$/) {
                print "You'll have to use 'kadmin' to add this user to the KDC.\n";
                print "Exiting...\n";
                exit(-1);
            }
        }
    }

    if ( ($errCode = createZfs($account)) != ERR_NONE) {
        print STDERR "Error while creating ZFS.\n";
        if (!checkExecMode(MODE_BATCH)) {
            print "Continue to verify? (y/N): ";
            $input = <STDIN>;
            if ($input =~ qr/[Nn]([Oo])?/ || $input =~ qr/^$/) {
                print "You'll have to use 'zfs create' to add this user to the ZPool.\n";
                print "Exiting...\n";
                exit(-1);
            }
        }
    }

    debugOutput("*makeAccount(): [$errCode]\n", DBL_FT);

    return $errCode;
}

sub logAccountCreation($;)
{
    my $account;
    my $errCode;

    $account = shift;

    debugOutput("*logAccountCreation(): [entry]\n", DBL_FT);
    if (!$account) {
        die "logAccountCreation: not passed needed arguments.";
    }

    if ( ($errCode = addToDoorAccessQueue($account)) != ERR_NONE) {
        print STDERR "Error while adding user to door access queue file ($DAQ_FILENAME).\n";
        if (!checkExecMode(MODE_BATCH)) {
            print "Continue on to account-verification steps? (y/N): ";
            $input = <STDIN>;
            if ($input =~ qr/[Nn]([Oo])?/ || $input =~ qr/^$/) {
                print "You'll have to edit the door access queue file ($DAQ_FILENAME) to add this user to the door access queue file.\n";
                print "(This file is in an NFS-mounted directory: nirvana:/export/srcit-notepad)\n";
                print "Exiting...\n";
                exit(-1);
            }
        }
    }
    if ( ($errCode = addToEmailQueue($account)) == ERR_SYSFAIL) {
        print "System error while adding user [$account->{ldapAccount}{uid}] to E-mail queue file ($EMAIL_QUEUE_FILE).\n";
        if (!checkExecMode(MODE_BATCH)) {
            print "Continue on to account-verification steps? (y/N): ";
            $input = <STDIN>;
            if ($input =~ qr/[Nn]([Oo])?/ || $input =~ qr/^$/) {
                print "You'll have to edit the door access queue file ($DAQ_FILENAME) to add this user to the door access queue file.\n";
                #print "(This file is in an NFS-mounted directory: nirvana:/export/srcit-notepad)\n";
                print "    located here: [$DAQ_FILENAME]\n";
                print "Exiting...\n";
                exit(-1);
            }
        }
    } elsif (ERR_INUSE == $errCode) {
        #TODO- grep the cumulative file to make sure!
        debugOutput("Skipping adding user to E-mail queue as this ldap account name already exists. (So, it has already been added once,probably)\n", DBL_DIAG);
    }
    #### else, err is ERR_NONE, continue ####

    #### NEW STUFF HERE FOR CWID / PIPELINE ID STORAGE ####
    #### add the info to the CWID DB ####
    if ( ($errCode = addToCwidDb($account)) != ERR_NONE) {
        print STDERR "Error while updating CWID DB [$CWID_FILENAME]\n";
        if (!checkExecMode(MODE_BATCH)) {
            print "Continue on to account-verification steps} (y/N): ";
            $input = <STDIN>;
            if ($input =~ qr/[Nn]([Oo])?/ || $input =~ qr/^$/) {
                print "You may want to update the CWID DB manually w/ the following information: \n";
                print "$account->{ldapAccount}{sn}, $account->{ldapAccount}{cn}    $account->{ldapAccount}{cwid}    $account->{ldapAccount}{mail}\n";
            }
        }
    }
                
    debugOutput("*logAccountCreation(): [exit]\n", DBL_FT);
    return $errCode;
}

sub addToCwidDb($;)
{
    my $account;
    my $errCode;

    my $fileName = $CWID_FILENAME;

    debugOutput("*addToCwidDb(): [entry]\n", DBL_FT);

    $account = shift;
    if (!$account) { die "addToCwidDb: not passed needed arguments!\n"; }

    $errCode = ERR_NONE;
    open(CWID_FH, ">>", "$fileName") or print "Error opening the CWID Database File ($fileName): $!\n", return ERR_SYSFAIL;
    
    if ($account->{ldapAccount}{cwid_status} == CWID_STAT_INPUT && checkExecMode(MODE_REAL)) {
        debugOutput("Updating CWID DB\n", DBL_DIAG);
        print "Adding CWID info for user [$account->{ldapAccount}{uid}] to CWID Database file.\n";

        #### what we actually want is a list w/ their pipelineIDs as well ####
        #TODO need to check when the account info is gotten from the DB that this user doesn't already have
        #an SRCIT username listed for the CWID / pipelineID that we are looking up

        print CWID_FH " $account->{ldapAccount}{sn}, $account->{ldapAccount}{cn}";
        print CWID_FH "        $account->{ldapAccount}{cwid}    $account->{ldapAccount}{pipelineID}";
        print CWID_FH "        $account->{ldapAccount}{uid}\n";

    } else {
        if ($account->{ldapAccount}{cwid_status} != CWID_STAT_FOUND && $account->{ldapAccount}{cwid_status} != CWID_STAT_INPUT 
            && $account->{ldapAccount}{cwid_status} != CWID_STAT_NA) {
            print "addToCwidDb: Fix me. I just saw a valued for {cwid_status} ([$account->{ldapAccount}{cwid_status}]) that I never should.\n";
            exit(ERR_INTERNAL);
        } elsif (!checkExecMode(MODE_REAL)) {
            print "Running in Test Mode. Skipping adding user's pipeline info  [$account->{ldapAccount}{pipelineID}] to CWID DB.\n";
        }
    }

    close(CWID_FH);

    debugOutput("*addToCwidDb(): [$errCode]\n", DBL_FT);
    return $errCode;

}

sub validatePassword($$$;)
{
    my ($password, $minPwLength, $rejectStr);
    my ($n, $passChar, $rejectChar, $passTmp, $rejectTmp);
    my $retVal;


    debugOutput("*validatePassword(): [entry]\n", DBL_FT);

    $password = shift;
    $minPwLength = shift;
    $rejectStr = shift;

    #if (!$password || !$minPwLength || !$rejectStr) { die "validatePassword: not passed needed arguments.\n" }
    ### allow rejectStr to be a null string ###
    if (!$password || !$minPwLength) { die "validatePassword: not passed needed arguments.\n" }

    $retVal = 1;

    debugOutput("validatePassword(): passed:\n", DBL_ALG);
    debugOutput("    password: [$password]:\n", DBL_ALG);
    debugOutput("    minPwLength: [$minPwLength]:\n", DBL_ALG);
    debugOutput("    rejectStr: [$rejectStr]:\n", DBL_ALG);

    ####  verify the length of the proposed password  ####
    if (length $password < $minPwLength) {
        $retVal = 0;
    }
    else {
        ####  test each character of the rejectStr against each character of the password  ####
        $passTmp = $password;
        while ( ($passChar = chop($passTmp)) !~ /^$/) {
            $rejectTmp = $rejectStr;

            while ($rejectChar = chop($rejectTmp)) {
                debugOutput("validatePassword(): [$rejectChar] eq? [$passChar]\n", DBL_ALG);
                if ($rejectChar eq $passChar) {
                    debugOutput("    YES\n", DBL_ALG);
                    $retVal = 0;
                } else {
                    debugOutput("    NO\n", DBL_ALG);
                }
            }
        }
    }

    debugOutput("*validatePassword(): [$retVal]\n", DBL_FT);
    
    return $retVal;
}


sub generatePassword($$;)
{
    my ($rejectString);
    my $pwLength;
    my ($password,$n);

    $pwLength = shift;
    $rejectString = shift;
    #if (!$pwLength || !$rejectString) { die "generatePassword: not passed needed arguments.\n"; }
    ### allow rejectString to be a null string ###
    if (!$pwLength) { die "generatePassword: not passed needed arguments.\n"; }

    debugOutput("*generatePassword():[entry]\n", DBL_FT);

    ####    use pwgen, and double check to make sure it doesn't have any unwanted characters  ####
    $n=1;
    do {
        debugOutput( "Attempt [$n] at generating password\n", DBL_ALG);

        ####  strip the trailing [space\n] sequence returned by pwgen  ####
        $password = `/opt/csw/bin/pwgen -sncy $pwLength 1`;
        chomp $password;

        debugOutput("Password [$n]: [$password]\n", DBL_ALG);
        $n++;

    }while (validatePassword($password,$pwLength,$rejectString) != 1);
 
    debugOutput("*generatePassword():[$password]\n", DBL_FT);
    return $password;
}


sub checkExistingCreds($;)
{
    my $cc;
    my $cc_cursor;
    my $creds;
    my $needed_princ_name;
    my $i;
    my $needed_creds_found;

    debugOutput("checkExistingCreds(): [entry]\n", DBL_FT);
    $needed_princ_name = 'sysadmin@PHY.STEVENS-TECH.EDU';
    #$needed_princ_name = shift;

    Authen::Krb5::init_context() || return 0;
    $cc = Authen::Krb5::cc_default() || return 0;


    $needed_creds_found = 0;
    $i = 0;
    $cc_cursor  = $cc->start_seq_get() || return 0;
    $creds = $cc->next_cred($cc_cursor) || return 0;
    while ($creds) {
        $i++;
        if ($creds->client() =~ /^$needed_princ_name$/) {
            if (time() >= $creds->starttime()) {
                if (time() <=  $creds->endtime()) {
                    $needed_creds_found = 1;
                 }
            }
        }
        $creds = $cc->next_cred($cc_cursor);
    }
    $cc->end_seq_get($cc_cursor);

    debugOutput("*checkExistingCreds(): [$needed_creds_found]\n", DBL_FT);
    return $needed_creds_found;
}

sub outputTicketBlurb($$;)
{

    my $account;
    my ($infile);
    my ($outfileName, $outfileHandle);
    my $inline;
    my $passString;
    my $USERNAME_TOKEN = qw(<username>);
    my $PASS_STRING_TOKEN = qw(<pass_string>);

    debugOutput("outputTicketBlurb():[entry]\n", DBL_FT);

    $account = shift;  
    die "outputTicketBlurb: not passed needed arguments." unless $account;
    $outfileName = shift;
    $outfileName = DEFAULT_TICKET_NOTE_FILE unless $outfileName;

    open( $infile, "<", NEW_ACCOUNT_BLURB_FILE) || die "Couldn't open
          NEW_ACCOUNT_BLURB_FILE.\n";

    if (!open ( $outfileHandle, ">", $outfileName)) {
        print "Couldn't open [$outfileName] for output. Using STDOUT.\n";
        $outfileHandle = STDOUT;
    }

    print $outfileHandle "\n";
    print $outfileHandle "**************************************************\n";

    print $outfileHandle "$account->{ldapAccount}{cn} $account->{ldapAccount}{sn},\n";

    while (defined($inline = <$infile>)) {
        if ( $inline =~ m/$USERNAME_TOKEN/) {

            $inline =~ s/$USERNAME_TOKEN/$account->{ldapAccount}{uid}/;
        } elsif ($inline =~ m/$PASS_STRING_TOKEN/) {

            # don't output the full password: remove the 8 digit CWID
            $passString = $account->{krb5Princ}{password};
            substr($passString, -8) = "";

            $inline =~ s/$PASS_STRING_TOKEN/$passString/;
        }

        print $outfileHandle $inline;
    }

    print "**************************************************\n";
    print "\n";

    debugOutput("*outputTicketBlurb():[]\n", DBL_FT);
    return;
}

sub updateTicket($$$;)
{
   
    my ($ticketNumber, $ticketTextFile);
    my ($inputFH, $outputFH);
    my ($mailProg, $mailFromAddr, $mailToAddr, $mailSubject, $mailText);
    my $headerFileName;


    debugOutput("updateTicket(): [entry]\n", DBL_FT);
    $account = shift;
    die "updateTicket: not passed needed arguments\n" unless $account;

    $ticketNumber = shift;
    if (!$ticketNumber) {
        print "updateTicket: not passed needed arguments.\n";
        print "updateTicket: can not update ticket without a ticket number.\n";
        print "updateTicket: update ticket by hand with the following text.\n";
    }

    $ticketTextFile = shift;
    if (!$ticketTextFile) {
        print "updateTicket: not passed needed arguments.\n";
        print "updateTicket: not given name of file to get ticket note from.\n";
    }


    outputTicketBlurb($account, $ticketTextFile);

    #make the fields for the mail program
    $mailProg = DEFAULT_MAILUTILS_MAIL;
    $mailFromAddr = MAIL_ADDR_SRCIT_TECH;
    $mailToAddr = MAIL_ADDR_HELPDESK;
    $mailSubject = "Ticket:$ticketNumber Action:TechUpdate Hidden:NO";
    $mailSubject .= " Status:Resolved EmailClient:YES";
    $mailSubject .= " Reassign: MinutesWorked:";
    
    debugOutput("mail: subject [$mailSubject]\n", DBL_ALG);

    #enable slurp to grab all of the ticket note text
    #local $/ = "";
    #if (!open($inputFH, "<", $ticketTextFile)) {
    #    die "Couldn't open the ticketing input file, $ticketTextFile: $!\n";
    #}
    # slurp it all in in one go thanks to the localized setting of $/
    #$mailText = <$inputFH>;

    #use the text in $ticketTextFile + ticketNumber to send an email to helpdesk

    #we have to make a file with the email headers, then prepend that to the
    #ticket text.
    #this hack is done b/c GNUmail doesn't exist on d* and can't be installed
    #due to massive out of date lib deps.
    
    $headerFileName="/tmp/.addu$$.headers";
    if (!open($outputFH, ">", $headerFileName)) { 
        die "updateTicket: can't open file for email headers: $!\n";
    }

    print $outputFH "From: $mailFromAddr\n";
    #print $outputFH "To: $mailToAddr\n";
    print $outputFH "Subject: $mailSubject\n";
    print $outputFH "\n";
    close($outputFH);

    $retv = \
    qx(cat \"$headerFileName\" \"$ticketTextFile\" | $mailProg -t $mailToAddr || echo "FAILURE");
       
    unlink $headerFileName;
    unlink $ticketTextFile;

    if ($retv eq "FAILURE") {
        print "updateTicket: mail command failed: $!\n";
        debugOutput("*updateTicket(): [ERR_SYSFAIL]\n", DBL_FT);
        return ERR_SYSFAIL;
    }

    debugOutput("*updateTicket(): [ERR_NONE]\n", DBL_FT);
    return ERR_NONE;
}

sub getTicketNumber(;)
{
    my $tktNum;

    debugOutput("getTicketNumber(): [entry]\n", DBL_FT);

    $tktNum = 0;
    do {
        print "Ticket Number (0 for no ticket updates): ";
        chomp($tktNum = <STDIN>);
    } while ($tktNum !~ m/^[0-9]+$/);

    if ($tktNum == 0) {
        print "Ticket number 0; no ticket update(s) will be sent.\n";
    }

    debugOutput("*getTicketNumber(): [$tktNum]\n", DBL_FT);

    return $tktNum;
}
