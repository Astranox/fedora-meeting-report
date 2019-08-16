## Fedora Meeting Report Generator

I whipped up this script to build reports for the Fedora Security Team meetings, but it could be adatped easily to fit the needs of other groups that use Bugzilla as their ticketing system.

Should work on Python 3.4+.

### Install Prerequisites

The script needs terminaltables, python-bugzilla, parsedatetime, SQLAlchemy and requests to work:

    pip3 install -r requirements.txt

### Running the script

Simply run the script:

    python3 report_generator.py

    python3 report_generator.py [--help] [--cron | --fetch | --date DATE]

### Sample output

      __          _
     / _| ___  __| | ___  _ __ __ _
    | |_ / _ \/ _` |/ _ \| '__/ _` |  Fedora Security Team Report
    |  _|  __/ (_| | (_) | | | (_| |  Report date: 2015-09-02 21:55:33.305011
    |_|  \___|\__,_|\___/|_|  \__,_|  Data from: 2015-09-02
    -------------------------------------------------------------------------------

    ┌Tickets by Priority──┬───────┬─────────┐
    │ Priority    │ Count │ Owned │ Unowned │
    ├─────────────┼───────┼───────┼─────────┤
    │ medium      │ 378   │ 43    │ 335     │
    │ low         │ 153   │ 14    │ 139     │
    │ high        │ 42    │ 22    │ 20      │
    │ unspecified │ 3     │ 0     │ 3       │
    └─────────────┴───────┴───────┴─────────┘

    ┌Tickets by Status─┬───────┬─────────┐
    │ Status   │ Count │ Owned │ Unowned │
    ├──────────┼───────┼───────┼─────────┤
    │ NEW      │ 495   │ 68    │ 427     │
    │ ON_QA    │ 44    │ 5     │ 39      │
    │ ASSIGNED │ 25    │ 6     │ 19      │
    │ MODIFIED │ 12    │ 0     │ 12      │
    └──────────┴───────┴───────┴─────────┘

    ┌Tickets by Severity──┬───────┬─────────┐
    │ Severity    │ Count │ Owned │ Unowned │
    ├─────────────┼───────┼───────┼─────────┤
    │ medium      │ 378   │ 43    │ 335     │
    │ low         │ 153   │ 14    │ 139     │
    │ high        │ 43    │ 22    │ 21      │
    │ unspecified │ 2     │ 0     │ 2       │
    └─────────────┴───────┴───────┴─────────┘

    ┌Tickets by Component──┬───────┬─────────┐
    │ Component    │ Count │ Owned │ Unowned │
    ├──────────────┼───────┼───────┼─────────┤
    │ cacti        │ 10    │ 0     │ 10      │
    │ nagios       │ 9     │ 9     │ 0       │
    │ moodle       │ 8     │ 1     │ 7       │
    │ quassel      │ 7     │ 0     │ 7       │
    │ qemu         │ 7     │ 4     │ 3       │
    │ mingw-icu    │ 7     │ 0     │ 7       │
    │ bugzilla     │ 7     │ 0     │ 7       │
    │ glibc        │ 6     │ 0     │ 6       │
    │ avr-binutils │ 6     │ 0     │ 6       │
    └──────────────┴───────┴───────┴─────────┘

    ┌Tickets by Distro Version─┬───────┬─────────┐
    │ Distro Version │ Tickets │ Owned │ Unowned │
    ├────────────────┼─────────┼───────┼─────────┤
    │ 21             │ 126     │ 7     │ 119     │
    │ 22             │ 130     │ 3     │ 127     │
    │ 23             │ 33      │ 11    │ 22      │
    │ 6.6            │ 1       │ 0     │ 1       │
    │ el5            │ 67      │ 20    │ 47      │
    │ el6            │ 210     │ 37    │ 173     │
    │ epel7          │ 36      │ 4     │ 32      │
    │ rawhide        │ 3       │ 0     │ 3       │
    │ unspecified    │ 3       │ 0     │ 3       │
    └────────────────┴─────────┴───────┴─────────┘
