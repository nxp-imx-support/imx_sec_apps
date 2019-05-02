#!/usr/bin/python
"""Cast certificate generation and signing tool.

This program can be used to generate and sign different certificate types for
Cast devices, including:

- Manufacturer certificate signing requests for fulfillment by Google
- Model certificates, signed with a manufacturer private key
- Device certificates for platform-managed provisioning, signed with a
  model private key
- Device certificate templates for model-based provisioning

The help screens are meant to be self guiding.  Running this tool without
any command line options will give instructions for getting started, and
how to see detailed instructions for each operation.

This program was developed using Python 2.7 on Ubuntu 14.04.  Other
configurations have not been tested, but only standard modules are
used.
"""

# Disable erroneous lint errors from regular expressions (b/19232653)
# pylint: disable=anomalous-backslash-in-string

from __future__ import print_function

import argparse
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from textwrap import TextWrapper

_MAJOR_VER = 1
_MINOR_VER = 0
_PATCH_VER = 1
__version__ = "%d.%d.%d" % (_MAJOR_VER, _MINOR_VER, _PATCH_VER)


class OptionParser(argparse.ArgumentParser):
  """ArgumentParser derived class that specializes help screens.

  The default ArgumentParser help-screen behavior is very simple, providing
  an automatically-generated list of registered options and descriptions.
  Although this class replaces the automatic help-screen generation with more
  or less static text, it allows us to tailor instructions to users and help
  them use the tool properly.

  Overriding this class also allows us to send error messages to the logger
  module.
  """

  def __init__(self, prog, add_help):
    self.__help_printed = False
    prog = os.path.basename(prog)
    super(OptionParser, self).__init__(prog=prog, add_help=add_help)

  def error(self, message):
    self.print_help()
    logging.error(message)

  def print_help(self):
    if self.__help_printed:
      return
    self.__help_printed = True

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    self.__print_common_help()
    print("Commands:")

    print("")
    print("  config")
    info = ("Configure OEM-specific information (name, location, etc.).  This "
            "must be run prior to any other commands.")
    twrap.initial_indent = " " * 4
    twrap.subsequent_indent = " " * 4
    print(twrap.fill(info))

    print("")
    print("  genman")
    info = ("Generate a manufacturer certificate signing request for "
            "fulfillment by Google.")
    print(twrap.fill(info))

    print("")
    print("  genmod")
    info = ("Generate a model certificate, and sign it with a manufacturer "
            "private key.")
    print(twrap.fill(info))

    print("")
    print("  gendev")
    info = ("Generate a device certificate for platform-managed provisioning, "
            "and sign it with the model private key.")
    print(twrap.fill(info))

    print("")
    print("  gendev-templ")
    info = ("Generate a device certificate template for model-based "
            "provisioning.")
    print(twrap.fill(info))

    twrap.initial_indent = " " * 2
    twrap.subsequent_indent = " " * 2
    print("")
    info = ("By default, all operations are performed inside of a temporary "
            "working directory inside of an encrypted RAM filesystem.  If "
            "needed, this can be overridden using the --working-dir option "
            "(see below).")
    print(twrap.fill(info))

    print("")
    self.__print_optional_args()
    print("")
    print("Run \"%s {command} --help\" to see a list of command options." %
          self.prog)
    print("")

  def print_command_help(self, command):
    """Prints help information for a specific command."""
    if self.__help_printed:
      return
    self.__help_printed = True

    self.__print_common_help(command)
    if command == "config":
      self.__print_config_help()
    if command == "genman":
      self.__print_genman_help()
    if command == "genmod":
      self.__print_genmod_help()
    if command == "gendev":
      self.__print_gendev_help()
    if command == "gendev-templ":
      self.__print_gendev_templ_help()
    print("")
    self.__print_optional_args()
    print("")

  def __print_optional_args(self):
    """Prints help information for optional arguments."""

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    print("Optional Arguments:")
    print("")
    print("  --config-file FILE")
    info = ("Location of file that holds OEM configuration data.  The default "
            "is ${HOME}/.castcert.rc")
    twrap.initial_indent = " " * 4
    twrap.subsequent_indent = " " * 4
    print("")
    print(twrap.fill(info))
    print("")
    print("  --working-dir DIRECTORY")
    info = ("Store intermediate files in the specified directory, instead of "
            "using the default encrypted ram filesystem.  USE WITH CAUTION!  "
            "The working directory will hold sensitive private keys that "
            "must be rigorously protected.")
    twrap.initial_indent = " " * 4
    twrap.subsequent_indent = " " * 4
    print("")
    print(twrap.fill(info))
    print("")
    print("  --debug")
    info = "Print verbose logs and commands while running."
    twrap.initial_indent = " " * 4
    twrap.subsequent_indent = " " * 4
    print("")
    print(twrap.fill(info))
    print("")
    print("  --help/-h")
    info = "When used with a command, command-specific options are listed."
    twrap.initial_indent = " " * 4
    twrap.subsequent_indent = " " * 4
    print("")
    print(twrap.fill(info))
    return

  def __print_common_help(self, command=None):
    if command is None:
      command = "{command}"
    print("Usage: %s %s {command options}" % (self.prog, command))
    print("")

  def __print_config_help(self):
    """Prints help information for the "config" command."""

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    print("  Required options for \"config\":")
    print("    None")
    print("")
    print("    Example Usage:")
    info = "%s config" % self.prog
    twrap.initial_indent = " " * 8
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))

  def __print_genman_help(self):
    """Prints help information for the "genman" command."""

    twrap = TextWrapper()

    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    print("  Required options for \"genman\":")
    print("")
    print("    --oem-postop PROGRAM")
    info = ("After the manufacturer certificate signing request and private "
            "key are generated, this OEM-supplied program or script is "
            "invoked.  The program must wrap/encrypt the generated "
            "manufacturer private key, and copy it and the certificate "
            "signing request from %s's temporary working directory.  "
            "The program must accept two arguments:") % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Path to the manufacturer certificate signing request in the "
            "temporary working directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))
    print(" " * 8 + "Argument 2: FILE")
    info = ("Path to the manufacturer private key in the temporary working "
            "directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))
    print("")
    print("    Example Usage:")
    info = "%s genman --oem-postop /path/to/oem_postop.sh" % self.prog
    twrap.width = 77
    twrap.initial_indent = " " * 8
    twrap.subsequent_indent = " " * 10

    # Put \ at the end of the lines to make it a valid command.  Also
    # un-munge Cast Audio Speaker to "Cast Audio Speaker" after the word-wrap
    # operation is complete.
    lines = twrap.wrap(info)
    twrap.width = 79
    for line in lines[:-1]:
      print(line + " \\")
    print(lines[-1])

  def __print_genmod_help(self):
    """Prints help information for the "genmod" command."""

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    print("  Required options for \"genmod\":")
    print("")
    print("    --oem-preop PROGRAM")
    info = ("Before generating the model certificate and key, this "
            "OEM-supplied program or script is invoked.  The program must "
            "unwrap/decrypt the manufacturer private key, and copy it into "
            "%s's temporary working directory where it can be used for "
            "signing.  The program must accept a single argument:"
           ) % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Destination filename of the unwrapped manufacturer private key "
            "in the temporary working directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))

    print("")
    print("    --oem-postop PROGRAM")
    info = ("After the model certificate chain and private key are "
            "generated, this OEM-supplied program or script is invoked.  "
            "The program must wrap/encrypt the generated model private key, "
            "and copy it and the model certificate chain from %s's temporary "
            "working directory.  The program must accept two arguments:"
           ) % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Path to the model certificate chain in the temporary working "
            "directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))
    print(" " * 8 + "Argument 2: FILE")
    info = "Path to the model private key in the temporary working directory."
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))

    print("")
    print("    --cert-chain FILE")
    info = ("Path to the manufacturer certificate chain provided by Google.")
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    --model-name STRING")
    info = "The OEM's official model name to be used in the model certificate."
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    --serial INTEGER")
    info = ("A unique serial number for the model certificate.  When "
            "possible, this should correspond to an OEM's official model "
            "ID.  It must be a positive integer not longer than 20 bytes.")
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    Example Usage:")
    info = ("%s genmod "
            "--oem-preop /path/to/oem_preop.sh "
            "--oem-postop /path/to/oem_postop.sh "
            "--cert-chain /path/to/manufacturer.crt "
            "--model-name \"Cast@Audio@Speaker\""
            "--serial 871264144") % self.prog
    twrap.width = 77
    twrap.initial_indent = " " * 8
    twrap.subsequent_indent = " " * 10

    # Put \ at the end of the lines to make it a valid command.  Also
    # replace "@" characters with spaces, which were used to prevent unwanted
    # line breaks.
    lines = twrap.wrap(info)
    twrap.width = 79
    for line in lines[:-1]:
      print(line.replace("@", " ") + " \\")
    print(lines[-1].replace("@", " "))

  def __print_gendev_help(self):
    """Prints help information for the "gendev" command."""

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    print("  Required options for \"gendev\":")
    print("")
    print("    --oem-preop PROGRAM")
    info = ("Before generating the device certificate and key, this "
            "OEM-supplied program or script is invoked.  The program must "
            "unwrap/decrypt the model private key, and copy it into "
            "%s's temporary working directory where it can be used for "
            "signing.  The program must accept a single argument:"
           ) % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Destination filename of the unwrapped model private key in the "
            "temporary working directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))

    print("")
    print("    --oem-postop PROGRAM")
    info = ("After the device certificate chain and private key are "
            "generated, this OEM-supplied program or script is invoked.  The "
            "program must wrap/encrypt the generated device private key, and "
            "copy it and the device certificate from %s's temporary working "
            "directory.  The program must accept two arguments:") % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Path to the device certificate chain in the temporary working "
            "directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))
    print(" " * 8 + "Argument 2: FILE")
    info = "Path to the device private key in the temporary working directory."
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))
    info = ("IMPORTANT:  The OEM-supplied program must wrap the device key "
            "such that it can be successfully unwrapped by the OEM-supplied "
            "libcast_auth.so library used by the Cast receiver.")
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    --cert-chain FILE")
    info = "Path to the model certificate chain."
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    --hardware-id <UNIQUE HARDWARE ID>")
    info = ("A unique hardware ID for the device.  It must be an alphanumeric "
            "string not greater than 20 characters long.")
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    Example Usage:")
    info = ("%s gendev "
            "--oem-preop /path/to/oem_preop.sh "
            "--oem-postop /path/to/oem_postop.sh "
            "--cert-chain /path/to/model.crt "
            "--hardware-id 230482323") % self.prog
    twrap.width = 77
    twrap.initial_indent = " " * 8
    twrap.subsequent_indent = " " * 10

    # Put \ at the end of the lines to make it a valid command.  Also
    # un-munge Cast Audio Speaker to "Cast Audio Speaker" after the word-wrap
    # operation is complete.
    lines = twrap.wrap(info)
    twrap.width = 79
    for line in lines[:-1]:
      print(line + " \\")
    print(lines[-1])
    return

  def __print_gendev_templ_help(self):
    """Prints help information for the "gendev-templ" command."""

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79

    print("  Required options for \"gendev-templ\":")
    print("")
    print("    --oem-preop PROGRAM")
    info = ("Before generating the device certificate template, this "
            "OEM-supplied program or script is invoked.  The program must "
            "unwrap/decrypt the model private key, and copy it into "
            "%s's temporary working directory where it can be used for "
            "signing.  The program must accept a single argument:"
           ) % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Destination filename of the unwrapped model private key in the "
            "temporary working directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))

    print("")
    print("    --oem-postop PROGRAM")
    info = ("After the device certificate template chain is generated, this "
            "OEM-supplied program or script is invoked.  The program must "
            "copy the generated certificate template chain from %s's "
            "temporary working directory.  The program must accept a single "
            "argument:") % self.prog
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))
    print(" " * 8 + "Argument 1: FILE")
    info = ("Path to the device template certificate chain in the temporary "
            "working directory.")
    twrap.initial_indent = " " * 10
    twrap.subsequent_indent = " " * 10
    print(twrap.fill(info))

    print("")
    print("    --cert-chain FILE")
    info = "Path to the model certificate chain."
    twrap.initial_indent = " " * 6
    twrap.subsequent_indent = " " * 6
    print("")
    print(twrap.fill(info))

    print("")
    print("    Example Usage:")
    info = ("%s gendev-templ "
            "--oem-preop /path/to/oem_preop.sh "
            "--oem-postop /path/to/oem_postop.sh "
            "--cert-chain /path/to/model.crt") % self.prog
    twrap.width = 77
    twrap.initial_indent = " " * 8
    twrap.subsequent_indent = " " * 10

    # Put \ at the end of the lines to make it a valid command.  Also
    # un-munge Cast Audio Speaker to "Cast Audio Speaker" after the word-wrap
    # operation is complete.
    lines = twrap.wrap(info)
    twrap.width = 79
    for line in lines[:-1]:
      print(line + " \\")
    print(lines[-1])
    return


class OEMInfo(object):
  """Manages persistent OEM information such as name and locality."""

  def __init__(self, config_file=None):
    self.__config = {
        "country_name":
        ["C", "Country Name (2 letter code)", None],
        "state_or_province_name":
        ["ST", "State or Province Name (full name)", None],
        "locality_name":
        ["L", "Locality Name (eg, city)", None],
        "oem_name":
        [None, "OEM Name", None]
    }

    if config_file is not None:
      self.__config_file = config_file
    else:
      self.__config_file = os.path.join(os.environ["HOME"], ".castcert.rc")

  def cert_fprefix(self, *args):
    """Constructs the filename prefix for a generated certificate or key.

    Input fields for the certificate and/or key generation are used
    to construct meaningful names for output files.

    Args:
        *args: Certificate-specific argument list.

    Returns:
        str: The constructed filename prefix.
    """

    result = ""

    if self.__config["oem_name"] is not None:
      result += self.__config["oem_name"][-1].lower()

    if self.__config["oem_name"] is not None:
      if len(args) >= 1 and args[0] == "manufacturer":
        result += "_Cast Audio"
      elif len(args) >= 2 and args[0] == "model":
        result += "_" + args[1].strip()
      elif len(args) >= 2 and args[0] == "device-templ":
        result += "_template"
      elif len(args) >= 2 and args[0] == "device":
        result += "_%s" % args[1].strip()

    result = result.strip()
    result = result.lower()
    result = result.replace(" ", "_")
    return result

  def gen_subj(self, *args):
    """Constructs the subject field for a certificate.

    Input fields for the certificate and/or key generation are used
    to construct meaningful names for output files.

    Args:
        *args: Certificate-specific argument list.

    Returns:
        str: The constructed subject line.
    """

    result = ""

    # First populate OEM-configured strings
    key_order = ["country_name", "state_or_province_name", "locality_name"]

    # Fields other than /CN are only generated for non-device certificates
    if len(args) < 1 or args[0] != "device":
      for key in key_order:
        setting = self.__config[key]
        if setting[-1] is not None:
          result += "/" + setting[0] + "=" + setting[-1]

      # organization name is the OEM name
      if self.__config["oem_name"] is not None:
        result += "/O=" + self.__config["oem_name"][-1]

    # for manufacturer certs, the common name is "<OEM> Cast Audio"
    if self.__config["oem_name"] is not None:
      if len(args) >= 2 and args[0] == "manufacturer":
        result += "/CN=" + self.__config["oem_name"][-1] + " Cast Audio"

    # for model certs, the common name is "<OEM> <Model>"
    if self.__config["oem_name"] is not None:
      if len(args) >= 2 and args[0] == "model":
        result += "/CN=" + self.__config["oem_name"][-1] + " " + args[1]

    # For device certs, the common name is "<UNIQUE HARDWARE ID> <BSS ID>".
    if self.__config["oem_name"] is not None:
      if len(args) >= 2 and args[0] == "device":
        # Check for proper formatting of hardware ID
        hardware_id = args[1].strip()
        if len(hardware_id) > 20:
          logging.warning("hardware id \"%s\" is greater than 20 characters",
                          hardware_id)

        # Make sure the id is alphanumeric
        if re.match("[A-Za-z0-9]{1,20}$", hardware_id) is None:
          logging.warning("hardware id \"%s\" is not alphanumeric", hardware_id)

        # Pad the hardware id with zeroes
        hardware_id = ("0" * (20 - len(hardware_id)) + hardware_id).upper()

        # The BSS ID is randomly generated using "fa:8f:ca" as the first three
        # bytes to enable discovery by the Google Cast app.
        bss_id = "fa8fca"
        three_bytes = os.urandom(3)
        for byte in three_bytes:
          bss_id += "%02x" % ord(byte)

        result += "/CN=%s %s" % (hardware_id, bss_id.upper())

    return result

  def load_config(self):
    if not os.access(self.__config_file, os.R_OK):
      return False

    with open(self.__config_file, "r") as ins:
      try:
        self.__config = json.load(ins)
      except json.JSONDecodeError:
        return False
    return True

  def save_config(self):
    """Save OEM configuration settings.

    Returns:
        bool: True if OEM configuration was successfully saved, False otherwise
    """

    dirname = os.path.dirname(os.path.realpath(self.__config_file))
    if not os.access(dirname, os.W_OK):
      logging.warning("cannot write OEM configuration file \"%s\"",
                      self.__config_file)
      return False

    with open(self.__config_file, "w") as output:
      try:
        json.dump(self.__config, output)
      except TypeError:
        return False
    return True

  def interactive_load_config(self):
    """Interactive prompts to set OEM configuration informatoin.

    Returns:
        bool: True if configuration was successfully entered, False otherwise
    """

    key_order = [
        "oem_name", "country_name", "state_or_province_name", "locality_name"
    ]

    for key in key_order:
      setting = self.__config[key]
      if setting[-1] is None:
        setting[-1] = ""
      user_input = raw_input("%s [%s]: " % (setting[1], setting[-1]))
      if user_input.rstrip():
        setting[-1] = user_input
      self.__config[key] = setting
    return True


class FileAccessVerifier(object):
  """Registers and checks the access modes of files that will be accessed.

  Every file that is read or written is first registered with this class
  during initialization, so we can fail quickly if there is a missing
  dependence on the host system.
  """

  def __init__(self):
    self.__rfiles = []
    self.__wfiles = []
    return

  def register_file_list(self, files, access):
    result = True
    files.sort()
    for cfile in files:
      if not self.register_file(cfile, access):
        result = False
    return result

  def register_file(self, cfile, access):
    if os.access(cfile, access):
      if access == os.R_OK:
        logging.info("\"%s\" is readable", cfile)
        self.__rfiles.append(cfile)
      elif access == os.W_OK:
        logging.info("\"%s\" is writable", cfile)
        self.__wfiles.append(cfile)
      return True
    else:
      if access == os.R_OK:
        logging.error("\"%s\" is not readable", cfile)
      elif access == os.W_OK:
        logging.error("\"%s\" is not writable", cfile)
      return False

  def is_file_verified(self, cfile, access):
    if access == os.R_OK and cfile not in self.__rfiles:
      logging.warning("read access to \"%s\" has not been verified")
      return False
    elif access == os.W_OK and cfile not in self.__wfiles:
      logging.warning("write access to \"%s\" has not been verified")
      return False
    return True


class CmdRunner(object):
  """Registers and checks the availability of programs that will be executed.

  Every program that is called is first registered with this class
  during initialization, so we can fail quickly if there is a missing
  dependence on the host system.  For each registered program, the PATH
  is searched to locate it, and executable access is verified.
  """

  def __init__(self, debug=False):
    self.__exes = {}
    self.__fcheck = FileAccessVerifier()
    self.__debug = debug

    if not debug:
      wfile_list = ["/dev/null"]
      self.__fcheck.register_file_list(wfile_list, os.W_OK)
    return

  def register_exe_list(self, exes):
    result = True
    exes.sort()
    for exe in exes:
      if not self.register_exe(exe):
        result = False
    return result

  def register_exe(self, exe, alt_name=None):
    """Register an executable that will be called.

    Args:
        exe: The name of the executable to register
        alt_name: An alias for the executable.
            If an alt_name is specified, the "run" command must be invoked
            using alt_name instead of the actual executable name.  This
            is convienient for calling user-specified executables.

    Returns:
        bool: True if the executable was located, False otherwise.
    """

    exe_path = self.__which(exe)
    if exe_path is not None:
      logging.info("using \"%s\" for \"%s\"", exe_path, exe)
      if alt_name is None:
        alt_name = exe
      self.__exes[alt_name] = exe_path
    else:
      logging.error("\"%s\" is not in your path", exe)
      return False
    return True

  def get_path(self, exe):
    if exe not in self.__exes:
      logging.error("location of program \"%s\" is not known", exe)
      return None
    return self.__exes[exe]

  def run(self, exe, *args):
    """Run a registered executable program in a subprocess.

    Args:
        exe: The registered name of the executable to run.
            If alt_name was specified when registering the execuable, it
            should be passed as the value for exe here.
        *args: Variable length list of arguments for the executable.

    Returns:
        int: The exit code of the subprocess.
    """
    if exe not in self.__exes:
      logging.error("location of program \"%s\" is not known", exe)
      return 1
    exe = self.__exes[exe]
    cmd = [exe] + list(args)
    rval = 0
    logging.info("command: %s", " ".join(cmd))

    dev_null = "/dev/null"
    if self.__debug or not self.__fcheck.is_file_verified(dev_null, os.W_OK):
      rval = subprocess.call(cmd)
    else:
      dn = open(dev_null, "w")
      rval = subprocess.call(cmd, stdout=dn, stderr=dn)
      dn.close()
    return rval

  def __which(self, exe):
    if os.access(os.path.realpath(exe), os.X_OK):
      return os.path.realpath(exe)
    for cdir in os.environ["PATH"].split(os.pathsep):
      cdir.strip('"')
      exe_path = os.path.join(cdir, exe)
      if os.path.isfile(exe_path) and os.access(exe_path, os.X_OK):
        return exe_path
    return None


class EncRamFs(object):
  """Manages a working directory using an encrypted RAM filesystem.

  This class first detects any ram filesystem (tmpfs) on the host, filters
  out the ones that are writeable by the current user, and picks the largest
  one.  It then creates an encrypted filesystem (encfs) using a 2048-byte
  random number from /dev/urandom as a passphrase.  When the object is
  shut down, the filesystem is released.
  """

  def __init__(self, debug=False):
    self.__exes = {}
    self.__fcheck = FileAccessVerifier()
    self.__debug = debug
    self.__ramfs = None
    self.__mntname = None
    self.__encfs_dir = None
    self.__encfs_mnt = None
    self.__cmd_runner = None
    self.__run = None
    return

  def initialize(self, mntname):
    """Detect a suitable ram filesystem, and create an encrypted directory."""

    self.__mntname = mntname

    prog_list = ["encfs", "fusermount", "sync", "dd"]
    self.__cmd_runner = CmdRunner(self.__debug)
    self.__run = self.__cmd_runner.run
    if not self.__cmd_runner.register_exe_list(prog_list):
      return False

    rfile_list = ["/proc/mounts", "/dev/urandom"]
    if not self.__fcheck.register_file_list(rfile_list, os.R_OK):
      return False

    # Locate a suitable ram filesystem for encrypted key storage
    self.__ramfs = self.__find_ramfs()
    if self.__ramfs is not None:
      logging.info("using \"%s\" for ramfs", self.__ramfs)
    else:
      return False
    return self.__create_encfs()

  def finalize(self):
    if not self.__encfs_dir:
      return False
    return self.__remove_encfs()

  def location(self):
    return self.__encfs_mnt

  def __find_ramfs(self):
    """Parse /proc/mounts to find a writeable ram filesystem."""

    viable_dirs = []
    proc_mounts = "/proc/mounts"
    if not self.__fcheck.is_file_verified(proc_mounts, os.R_OK):
      return None

    with open(proc_mounts, "r") as ins:
      for line in ins:
        fields = line.rstrip().split()
        if fields[2] == "tmpfs" and os.access(fields[1], os.W_OK):
          viable_dirs.append(fields[1])

    best_dir = None
    max_avail = 0
    for cdir in viable_dirs:
      avail = os.statvfs(cdir).f_bavail
      if avail > max_avail:
        best_dir = cdir
        max_avail = avail
    return best_dir

  def __create_encfs(self):
    """Create an encrypted filesystem with a random passphrase."""

    # Create temporary directory and mount point
    dirname = "." + self.__mntname
    mntpath = os.path.realpath(os.path.join(self.__ramfs, self.__mntname))
    dirpath = os.path.realpath(os.path.join(self.__ramfs, dirname))
    self.__encfs_dir = dirpath
    self.__encfs_mnt = mntpath
    os.mkdir(self.__encfs_dir)
    os.mkdir(self.__encfs_mnt)
    ret = self.__run("encfs", "--standard",
                     "--extpass=" + self.__cmd_runner.get_path("dd") +
                     " if=/dev/urandom bs=2048 count=1", self.__encfs_dir,
                     self.__encfs_mnt)

    if ret == 0:
      logging.info("encrypted filesystem mounted")
      logging.info("encfs directory:   \"%s\"", self.__encfs_dir)
      logging.info("encfs mount point: \"%s\"", self.__encfs_mnt)
    else:
      logging.error("failed to mount encrypted filesystem")
      shutil.rmtree(self.__encfs_mnt)
      shutil.rmtree(self.__encfs_dir)
      self.__encfs_dir = None
      self.__encfs_mnt = None
      return False
    return True

  def __remove_encfs(self):
    """Unmount and remove the encrypted filesystem."""

    ret = self.__run("sync")
    ret = self.__run("fusermount", "-u", self.__encfs_mnt)
    if ret != 0:
      logging.error("failed to unmount encrypted filesystem")
      return False
    try:
      shutil.rmtree(self.__encfs_mnt)
      shutil.rmtree(self.__encfs_dir)
    except shutil.Error:
      logging.error("failed to remove encfs directories")
    self.__encfs_mnt = None
    self.__encfs_dir = None
    return True


class App(object):
  """Encapsulates the main program routine.

  Reduces pollution of the global namespace by encapsulating the main program
  routines in this class, with the "main" method as the entry ponit.  As a
  result, the program is run using this simple command:

    sys.exit(App(sys.argv).main())
  """

  def __init__(self, argv):
    self.__argv = argv
    self.__encfs = None
    self.__fcheck = None
    self.__oem_info = None
    self.__op = None
    self.__options = None
    self.__optparse = None
    self.__ssl_cfg = "openssl_config"
    self.__sys_except = sys.excepthook
    self.__workdir = None

  def __initialize(self):
    """Initializes the program environment.

    This allows us to fail quickly if we detect missing resources needed to
    run.

    Returns:
        bool: True if initialization was successful, False otherwise.
    """

    # Located needed executables
    prog_list = ["openssl"]
    self.__cmd_runner = CmdRunner(self.__options.debug)
    self.__run = self.__cmd_runner.run
    if not self.__cmd_runner.register_exe_list(prog_list):
      return False

    # Create an encrypted ram filesystem manager if an alternate working
    # directory was not specified
    if self.__options.working_dir is None:
      self.__encfs = EncRamFs(self.__options.debug)

    if not self.__load_oem_config():
      logging.critical("could not load OEM configuration")
      return False

    mntname = os.path.splitext(os.path.basename(self.__argv[0]))[0]
    mntname += "-" + str(os.getpid())
    if self.__options.working_dir is None:
      print("")
      print("Creating Encrypted Filesystem...")
      if not self.__encfs.initialize(mntname):
        logging.critical("could not create encrypted filesystem")
        return False
      self.__workdir = self.__encfs.location()
    else:
      if not os.access(self.__options.working_dir, os.W_OK):
        logging.error("specified working directory \"%s\" is not writeable",
                      self.__options.working_dir)
        return False
      self.__workdir = os.path.join(self.__options.working_dir, mntname)
      os.mkdir(self.__workdir)
    return True

  def __finalize(self):
    # Since this gets called from our exception hook, we need to ensure things
    # get cleaned up properly without assuming too much about what state the
    # program is in.
    if self.__encfs is not None:
      if not self.__encfs.finalize():
        logging.critical("could not remove encrypted filesystem")

    if self.__workdir is not None and os.access(self.__workdir, os.W_OK):
      shutil.rmtree(self.__workdir)
    self.__workdir = None
    return True

  def except_hook(self, e_type, e_value, e_traceback):
    logging.critical("An unhandled exception occured; cleaning up and exiting")
    self.__finalize()
    self.__sys_except(e_type, e_value, e_traceback)

  def __load_oem_config(self):
    """Load persistent OEM information from the configuration file."""

    if self.__oem_info is not None:
      logging.error("OEM configuration already loaded")
      return False

    self.__oem_info = OEMInfo(self.__options.config_file)
    if not self.__oem_info.load_config():
      logging.error(("could not load OEM configuration; please re-run with "
                     "the \"config\" command"))
      return False
    return True

  def __expdays(self, cert_fname):
    """Calculate the number of days from now until a certificate expires.

    Args:
        cert_fname: The filename of the certificate that will be checked.

    Returns:
        int: The number of days until the certificate expires.
    """

    # Query the expiry date of the certificate
    openssl_exe = self.__cmd_runner.get_path("openssl")
    if openssl_exe is None:
      logging.error("location of program \"%s\" is not known", "openssl")
      return 0
    raw_date = subprocess.check_output(
        [openssl_exe, "x509", "-noout", "-enddate", "-in", cert_fname])

    # Extract date string from output
    dmatch = re.search("notAfter=(\S+) +(\d+) +(\d+):(\d+):(\d+) +(\d+) +(\S+)",
                       raw_date)
    month = dmatch.group(1)
    day = int(dmatch.group(2))
    hour = int(dmatch.group(3))
    mte = int(dmatch.group(4))
    sec = int(dmatch.group(5))
    year = int(dmatch.group(6))
    tz = dmatch.group(7)

    # Make a datetime object for the time
    dt_str = "%s%02d%02d%02d%02d%d%s" % (month, day, hour, mte, sec, year, tz)
    dt_fmt = "%b%d%H%M%S%Y%Z"
    dt_crt = datetime.datetime.strptime(dt_str, dt_fmt)
    logging.info("signing certificate expires: %s", str(dt_crt))

    if dt_crt < datetime.datetime.now():
      return 0
    else:
      days_remaining = (dt_crt - datetime.datetime.now()).days

    return days_remaining

  def __config(self):
    self.__oem_info = OEMInfo(self.__options.config_file)

    # Load previous values to use as defaults, if they exist
    self.__oem_info.load_config()

    self.__oem_info.interactive_load_config()
    return self.__oem_info.save_config()

  def __genman(self):
    """Generate a manufacturer certificate signing request."""

    if self.__options.oem_postop is None:
      logging.error("genmod must specify --oem-postop option")
      return False
    if not self.__cmd_runner.register_exe(self.__options.oem_postop, "postop"):
      return False

    # Calculate filenames
    cert_fprefix = self.__oem_info.cert_fprefix("manufacturer")
    mankey_fname = os.path.join(self.__workdir, "%s.key" % cert_fprefix)
    mancsr_fname = os.path.join(self.__workdir, "%s.csr" % cert_fprefix)

    print("Generating manufacturer key...")

    # Generate the manufacturer key
    ret = self.__run("openssl", "genrsa", "-out", mankey_fname, "2048")
    if ret != 0:
      return False

    # Generate the model certificate signing request
    mancsr_subj = self.__oem_info.gen_subj("manufacturer",
                                           self.__options.model_name)
    ret = self.__run("openssl", "req", "-new", "-key", mankey_fname, "-out",
                     mancsr_fname, "-subj", mancsr_subj)
    if ret != 0:
      return False

    # Copy certificate signing request + chan and wrap the new model key
    ret = self.__run("postop", mancsr_fname, mankey_fname)
    if ret != 0:
      return False

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79
    info = ("A manufacturer certificate signing request and private key "
            "have been successfully generated.  Please send the certificate "
            "signing request to Google for fulfillment.  Do not send the "
            "private key, but keep it in a secure location for signing model "
            "certificates.")
    print("")
    print(twrap.fill(info))

    return True

  def __genmod(self):
    """Generate a model certificate and private key."""

    # Required options
    if self.__options.oem_preop is None:
      logging.error("genmod must specify --oem-preop option")
      return False
    if self.__options.oem_postop is None:
      logging.error("genmod must specify --oem-postop option")
      return False
    if self.__options.cert_chain is None:
      logging.error("genmod must specify --cert-chain option")
      return False
    if self.__options.model_name is None:
      logging.error("genmod must specify --model-name option")
      return False
    if self.__options.serial is None:
      logging.error("genmod must specify --serial option")
      return False

    # Prohibited options
    if self.__options.hardware_id is not None:
      logging.error("genmod does not support --hardware-id option")
      return False

    # Check option values
    if not self.__cmd_runner.register_exe(self.__options.oem_preop, "preop"):
      return False
    if not self.__cmd_runner.register_exe(self.__options.oem_postop, "postop"):
      return False
    if not os.access(self.__options.cert_chain, os.R_OK):
      logging.error("\"%s\" cannot be read", self.__options.cert_chain)
      return False

    # Calculate filenames
    cert_fprefix = self.__oem_info.cert_fprefix("model",
                                                self.__options.model_name)
    modkey_fname = os.path.join(self.__workdir, "%s.key" % cert_fprefix)
    modcsr_fname = os.path.join(self.__workdir, "%s.csr" % cert_fprefix)
    modcrt_fname = os.path.join(self.__workdir, "%s-tmp.crt" % cert_fprefix)
    modchn_fname = os.path.join(self.__workdir, "%s.crt" % cert_fprefix)
    mankey_fname = os.path.join(self.__workdir, "man.key")
    mancrt_fname = os.path.join(self.__workdir, "man.crt")

    print("Generating model key from manufacturer key...")

    # Create an openssl config file
    ssl_cfg_template = """[ audio_model_ext ]
basicConstraints=CA:TRUE,pathlen:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = keyCertSign, cRLSign
certificatePolicies=1.3.6.1.4.1.11129.2.5.2
"""
    ssl_cfgname = os.path.join(self.__workdir, self.__ssl_cfg)
    with open(ssl_cfgname, "w") as cfgfile:
      cfgfile.write(ssl_cfg_template)

    # Generate the model key
    ret = self.__run("openssl", "genrsa", "-out", modkey_fname, "2048")
    if ret != 0:
      return False

    # Generate the model certificate signing request
    modcsr_subj = self.__oem_info.gen_subj("model", self.__options.model_name)
    ret = self.__run("openssl", "req", "-new", "-key", modkey_fname, "-out",
                     modcsr_fname, "-subj", modcsr_subj)
    if ret != 0:
      return False

    # Extract the manufacturer certificate from the cert chain.  It is assumed
    # to be the first entry in the chain.
    with open(mancrt_fname, "w") as outfile:
      with open(self.__options.cert_chain, "r") as infile:
        for line in infile:
          outfile.write(line)
          if line.rstrip() == "-----END CERTIFICATE-----":
            outfile.write("\n")
            break

    # Unwrap the manufacturer key
    ret = self.__run("preop", mankey_fname)
    if ret != 0:
      return False

    # Match the expiry date with the model cert
    days = self.__expdays(mancrt_fname)
    if days == 0:
      logging.error("manufacturer certificate has expired")
      return False

    # Sign the request with the manufacturer certificate
    ret = self.__run("openssl", "x509", "-req", "-days", str(days), "-extfile",
                     ssl_cfgname, "-extensions", "audio_model_ext", "-sha256",
                     "-CA", mancrt_fname, "-CAkey", mankey_fname, "-set_serial",
                     self.__options.serial, "-in", modcsr_fname, "-out",
                     modcrt_fname)
    if ret != 0:
      return False

    # Generate an updated cert chain
    merge_files = [modcrt_fname, self.__options.cert_chain]
    with open(modchn_fname, "w") as outfile:
      for fname in merge_files:
        with open(fname, "r") as infile:
          outfile.write(infile.read())

    # Copy new certificate + chan and wrap the new model key
    ret = self.__run("postop", modchn_fname, modkey_fname)
    if ret != 0:
      return False

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79
    info = ("A model certificate chain and private key have been "
            "successfully generated.  The model certificate is the first "
            "entry in the certificate chain.")
    print("")
    print(twrap.fill(info))

    return True

  def __gendev(self):
    """Generate a device certificate and private key."""

    # Required options
    if self.__options.oem_preop is None:
      logging.error("gendev must specify --oem-preop option")
      return False
    if self.__options.oem_postop is None:
      logging.error("gendev must specify --oem-postop option")
      return False
    if self.__options.cert_chain is None:
      logging.error("gendev must specify --cert-chain option")
      return False
    if self.__options.hardware_id is None:
      logging.error("gendev must specify --hardware_id option")
      return False

    # Prohibited options
    if self.__options.model_name is not None:
      logging.error("genmod does not support --model-name option")
      return False
    if self.__options.serial is not None:
      logging.error("genmod does not support --serial option")
      return False

    # Check option values
    if not self.__cmd_runner.register_exe(self.__options.oem_preop, "preop"):
      return False
    if not self.__cmd_runner.register_exe(self.__options.oem_postop, "postop"):
      return False
    if not os.access(self.__options.cert_chain, os.R_OK):
      logging.error("\"%s\" cannot be read", self.__options.cert_chain)
      return False

    # Calculate filenames
    cert_fprefix = self.__oem_info.cert_fprefix("device",
                                                self.__options.hardware_id)
    devkey_fname = os.path.join(self.__workdir, "%s.key" % cert_fprefix)
    devcsr_fname = os.path.join(self.__workdir, "%s.csr" % cert_fprefix)
    devcrt_fname = os.path.join(self.__workdir, "%s-tmp.crt" % cert_fprefix)
    devchn_fname = os.path.join(self.__workdir, "%s.crt" % cert_fprefix)
    modkey_fname = os.path.join(self.__workdir, "mod.key")
    modcrt_fname = os.path.join(self.__workdir, "mod.crt")

    print("Generating device key from model key...")

    # Create an openssl config file
    ssl_cfg_template = """[ audio_device ]
basicConstraints=CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
certificatePolicies=1.3.6.1.4.1.11129.2.5.2
"""
    ssl_cfgname = os.path.join(self.__workdir, self.__ssl_cfg)
    with open(ssl_cfgname, "w") as cfgfile:
      cfgfile.write(ssl_cfg_template)

    # Generate the device key
    ret = self.__run("openssl", "genrsa", "-out", devkey_fname, "2048")
    if ret != 0:
      return False

    # Generate the device certificate signing request
    devcsr_subj = self.__oem_info.gen_subj("device", self.__options.hardware_id)
    ret = self.__run("openssl", "req", "-new", "-key", devkey_fname, "-out",
                     devcsr_fname, "-subj", devcsr_subj)
    if ret != 0:
      return False

    # Extract the model certificate from the cert chain.  It is assumed
    # to be the first entry in the chain.
    with open(modcrt_fname, "w") as outfile:
      with open(self.__options.cert_chain, "r") as infile:
        for line in infile:
          outfile.write(line)
          if line.rstrip() == "-----END CERTIFICATE-----":
            outfile.write("\n")
            break

    # Unwrap the model key
    ret = self.__run("preop", modkey_fname)
    if ret != 0:
      return False

    # Generate a serial number (20-byte even integer)
    serial_bytes = list(os.urandom(20))
    serial_bytes[0] = chr(ord(serial_bytes[0]) & 0x7F)
    serial = "0x"
    for byte in serial_bytes:
      serial += "%02X" % ord(byte)

    # Match the expiry date with the model cert
    days = self.__expdays(modcrt_fname)
    if days == 0:
      logging.error("model certificate has expired")
      return False

    # Generate the certificate
    ret = self.__run("openssl", "x509", "-req", "-days", str(days), "-extfile",
                     ssl_cfgname, "-extensions", "audio_device", "-sha256",
                     "-CA", modcrt_fname, "-CAkey", modkey_fname, "-set_serial",
                     serial, "-in", devcsr_fname, "-out", devcrt_fname)
    if ret != 0:
      return False

    # Generate an updated cert chain
    merge_files = [devcrt_fname, self.__options.cert_chain]
    with open(devchn_fname, "w") as outfile:
      for fname in merge_files:
        with open(fname, "r") as infile:
          outfile.write(infile.read())

    # Copy new certificate + chan and wrap the new model key
    ret = self.__run("postop", devchn_fname, devkey_fname)
    if ret != 0:
      return False

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79
    info = ("A device platform certificate chain and private key "
            "have been successfully generated.  The device platform "
            "certificate is the first entry in the certificate chain.")
    print("")
    print(twrap.fill(info))

    return True

  def __gendev_templ(self):
    """Generate a device certificate template."""

    # Required options
    if self.__options.oem_preop is None:
      logging.error("gendev_templ must specify --oem-preop option")
      return False
    if self.__options.oem_postop is None:
      logging.error("gendev_templ must specify --oem-postop option")
      return False
    if self.__options.cert_chain is None:
      logging.error("gendev_templ must specify --cert-chain option")
      return False

    # Prohibited options
    if self.__options.model_name is not None:
      logging.error("genmod does not support --model-name option")
      return False
    if self.__options.serial is not None:
      logging.error("genmod does not support --serial option")
      return False
    if self.__options.hardware_id is not None:
      logging.error("genmod does not support --hardware-id option")
      return False

    # Check option values
    if not self.__cmd_runner.register_exe(self.__options.oem_preop, "preop"):
      return False
    if not self.__cmd_runner.register_exe(self.__options.oem_postop, "postop"):
      return False
    if not os.access(self.__options.cert_chain, os.R_OK):
      logging.error("\"%s\" cannot be read", self.__options.cert_chain)
      return False

    # Calculate filenames
    cert_fprefix = self.__oem_info.cert_fprefix("device-templ")
    devcsr_fname = os.path.join(self.__workdir, "%s.csr" % cert_fprefix)
    devcrt_fname = os.path.join(self.__workdir, "%s-tmp.crt" % cert_fprefix)
    devchn_fname = os.path.join(self.__workdir, "%s.crt" % cert_fprefix)
    modkey_fname = os.path.join(self.__workdir, "mod.key")
    modcrt_fname = os.path.join(self.__workdir, "mod.crt")

    print("Generating device key from model key...")

    # Create an openssl config file
    ssl_cfg_template = """[ audio_device ]
basicConstraints=CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
certificatePolicies=1.3.6.1.4.1.11129.2.5.2
"""
    ssl_cfgname = os.path.join(self.__workdir, self.__ssl_cfg)
    with open(ssl_cfgname, "w") as cfgfile:
      cfgfile.write(ssl_cfg_template)

    # Write the template CSR to a file
    template_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIICdjCCAV4CAQAwMTEvMC0GA1UEAwwmPFVOSVFVRSBIQVJEV0FSRSBJRD4gQUE6
QkI6Q0M6REQ6RUU6RkYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV
lg1+p5FwDun2TLF7keZvR6Pop5ysBeo5O5w11KSSWuQcA6FScPhos5lwT597NnyG
JZTEnhIfZv4bJrNzBWSrimLqwQuwnvs6Sy6Bb03Oe8gIhNADCKvdHfJlBYnwf5sF
FvUqC8VTQ5014Vl6rxde55W/ZY0mHZNZCtuqa4zS6rpUs353f1rOa6haQ2YObhhD
YApYFbfuxxKRbCPUqavpwvk7Rdh5mnvtpdeGqWwHHn3+ppqnvsgW5amzoW6PrXS4
dTB2kASJSBeL11DxuLrOOgdzhilNWG94uO1ExfB0FbN54fWueDHPYR5EoyK4h4wc
Zpmckx1Bh/rSSXPLVQ0dAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEATL0D923n
SNBTr4ru5bdeUFHJTitH5CPP3FZcccBLPxVAot95/flbnIy0Xbre7ew8i4sSeXmQ
AjAkAi85Ctkb6HIrzawzu7FAXKAd+/LMAEFT+tjyr4HBnQpaHFe0fgAb9gxZYeG4
WRADW1JeFTfdLvx4n0UGP07GAkUQOmUUpI9Pi1rPpnnhTlYGfqNLuw9Hp1A6Sk5P
1v69/7vXs9DuT4lv4H7dlrt+K6SzeX6HtdKflWqSHKNzAE4JI584gLmpABIz5Oot
MlPBHWqfFdxcxQohRFWV80kAjzuYOmAt87sYF6q77XvAFvfU5xS3fTY/A9C2kaRv
WbI1n2liQKA7QQ==
-----END CERTIFICATE REQUEST-----
"""
    with open(devcsr_fname, "w") as cfgfile:
      cfgfile.write(template_csr)

    # Extract the model certificate from the cert chain.  It is assumed
    # to be the first entry in the chain.
    with open(modcrt_fname, "w") as outfile:
      with open(self.__options.cert_chain, "r") as infile:
        for line in infile:
          outfile.write(line)
          if line.rstrip() == "-----END CERTIFICATE-----":
            break

    # Unwrap the model key
    ret = self.__run("preop", modkey_fname)
    if ret != 0:
      return False

    # Match the expiry date with the model cert
    days = self.__expdays(modcrt_fname)
    if days == 0:
      logging.error("model certificate has expired")
      return False

    # Generate the certificate template
    ret = self.__run("openssl", "x509", "-req", "-days", str(days), "-extfile",
                     ssl_cfgname, "-extensions", "audio_device", "-sha256",
                     "-CA", modcrt_fname, "-CAkey", modkey_fname, "-set_serial",
                     "0x3c434552542053455249414c204e554d4245523e", "-in",
                     devcsr_fname, "-out", devcrt_fname)
    if ret != 0:
      return False

    # Generate an updated cert chain
    merge_files = [modcrt_fname, self.__options.cert_chain]
    with open(devchn_fname, "w") as outfile:
      for fname in merge_files:
        with open(fname, "r") as infile:
          outfile.write(infile.read())

    # Copy new certificate + chan and wrap the new model key
    ret = self.__run("postop", devchn_fname)
    if ret != 0:
      return False

    twrap = TextWrapper()
    twrap.fix_sentence_endings = True
    twrap.break_on_hyphens = False
    twrap.width = 79
    info = ("A device certificate template and chain have been successfully "
            "generated.  The device certificate template is the first entry "
            "in the certificate chain.")
    print("")
    print(twrap.fill(info))

    return True

  def __parse_args(self):
    """Parse command line arguments."""

    self.__optparse = OptionParser(prog=self.__argv[0], add_help=False)

    # Arguments
    self.__optparse.add_argument(
        "command",
        action="store",
        choices=["config", "genman", "genmod", "gendev", "gendev-templ"])
    self.__optparse.add_argument("--oem-preop", action="store", default=None)
    self.__optparse.add_argument("--oem-postop", action="store", default=None)
    self.__optparse.add_argument("--cert-chain", action="store", default=None)
    self.__optparse.add_argument("--model-name", action="store", default=None)
    self.__optparse.add_argument("--serial", action="store", default=None)
    self.__optparse.add_argument("--hardware-id", action="store", default=None)
    self.__optparse.add_argument("--debug", action="store_true", default=False)
    self.__optparse.add_argument("--working-dir", action="store", default=None)
    self.__optparse.add_argument("--config-file", action="store", default=None)
    self.__optparse.add_argument(
        "--help", "-h", action="store_true", default=False)

    if len(self.__argv) < 2:
      self.__optparse.print_help()
      return False

    try:
      self.__options = self.__optparse.parse_args(self.__argv[1:])
    except argparse.ArgumentError:
      return False
    except TypeError:
      return False

    if self.__options.command == "config":
      self.__op = App.__config
    elif self.__options.command == "genman":
      self.__op = App.__genman
    elif self.__options.command == "genmod":
      self.__op = App.__genmod
    elif self.__options.command == "gendev":
      self.__op = App.__gendev
    elif self.__options.command == "gendev-templ":
      self.__op = App.__gendev_templ
    else:
      self.__optparse.print_help()
      return False

    if self.__options.help:
      if self.__options.command is not None:
        self.__optparse.print_command_help(self.__options.command)
        return False
      else:
        self.__optparse.print_help()
        return False

    return True

  def main(self):
    print("Cast Certificate Generator %s" % __version__)
    print("")

    # Gracefully handle program crashes, and cleanup encrypted filesystem
    sys.excepthook = self.except_hook

    logging.basicConfig(
        format="%(levelname)s:%(message)s", level=logging.WARNING)

    if not self.__parse_args():
      return 1

    # Turn on all logs when --debug is used
    if self.__options.debug:
      logging.getLogger().setLevel(logging.DEBUG)

    # Special handling for "config" command, since initiazation will fail
    # if configuration has not been done.
    if self.__options.command == "config":
      if not self.__op(self):
        logging.critical("%s operation failed", self.__options.command)
        return 1
      return 0

    print("Initializing...")
    if not self.__initialize():
      logging.critical("failed to initialize")
      return 1

    # Run specified command
    if self.__op is not None:
      if not self.__op(self):
        logging.critical("%s operation failed", self.__options.command)
        self.__optparse.print_command_help(self.__options.command)

    # Clean up
    if not self.__finalize():
      return 1

    print("")
    return 0

# Launch Program
sys.exit(App(sys.argv).main())
