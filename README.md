# Inspecquery powered by Osquery

Inspecquery is an Osquery extension for Chef InSpec. 

You can exec any InSpec profile by querying `inspec` table easily.

**For improving performance, any profile's result will be cached before expiry (1 minute).**

## Features

- [x] Support execute InSpec tests
- [x] Support local and remote profile
- [x] Support special any controls
- [x] Support cache test result (1 minute)

## Requirement

- Osquery
- [InSpec](https://github.com/inspec/inspec)

## Build extension

```bash
[root@centos]# git clone https://github.com/keepwn/inspecquery
[root@centos]# cd inspecquery
[root@centos]# make
```

## Usage

### start osqueryi with inspecquery

```bash
[root@centos]# chmod +x inspecquery
[root@centos]# osqueryi --allow_unsafe=true --extension=inspecquery
Using a virtual database. Need help, type '.help'
osquery>
```

### table schema

```sqlite
CREATE TABLE inspec(
    `profile_path` TEXT,
    `group` TEXT,
    `control` TEXT,
    `title` TEXT,
    `desc` TEXT,
    `description` TEXT,
    `impact` TEXT,
    `result` TEXT
);
```

### query table

you can set profile_path to any local or remote profile:

```sql
select * from inspec profile_path = "/root/cis-dil-benchmark-master"
select * from inspec profile_path = "https://github.com/dev-sec/cis-dil-benchmark"
```

you also can set control to run, and ignore all other tests:

```sql
... and control = "cis-dil-benchmark-1.1.1.1"
... and control IN ("cis-dil-benchmark-1.1.1.1","cis-dil-benchmark-1.1.1.3")
... and control LIKE "cis-dil-benchmark-1.1.1%"
```

```bash
osquery> .mode pretty
osquery> select `group`,id,title,impact,result from inspec where profile_path = "/root/cis-dil-benchmark-master" limit 10;
+------------------------------+---------------------------+-----------------------------------------------------+--------+--------+
| group                        | control                   | title                                               | impact | result |
+------------------------------+---------------------------+-----------------------------------------------------+--------+--------+
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.1 | Ensure mounting of cramfs filesystems is disabled   | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.2 | Ensure mounting of freevxfs filesystems is disabled | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.3 | Ensure mounting of jffs2 filesystems is disabled    | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.4 | Ensure mounting of hfs filesystems is disabled      | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.5 | Ensure mounting of hfsplus filesystems is disabled  | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.6 | Ensure mounting of squashfs filesystems is disabled | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.7 | Ensure mounting of udf filesystems is disabled      | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.1.8 | Ensure mounting of FAT filesystems is disabled      | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.2   | Ensure separate partition exists for /tmp           | 1      | failed |
| 1.1 Filesystem Configuration | cis-dil-benchmark-1.1.3   | Ensure nodev option set on /tmp partition           | 1      | failed |
+------------------------------+---------------------------+-----------------------------------------------------+--------+--------+
```
