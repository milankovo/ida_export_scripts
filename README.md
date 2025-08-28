# Export Git Plugin for IDA Pro
![logo](logo.jpg)

## Overview
The Export Git plugin for IDA Pro enables the seamless export of script snippets to a Git repository, ensuring your work is automatically backed up and version-controlled.

## Installation
1. Ensure that IDA Pro is installed on your system.
2. Clone or download this repository.
3. Copy the `export_to_git.py` file into the `plugins` directory of your IDA Pro installation.

## Usage
The plugin automatically exports all your script snippets to a Git repository when you close your IDA Pro project (saving is not required).

## Configuration
- The plugin requires a Git repository to be initialized in the specified export directory. Users must set this up before using the plugin.
- To customize the Git repository path, edit the list inside the `find_existing_script_directory` function in the `export_to_git.py` file. You can specify multiple paths, and the plugin will use the first existing folder it finds. By default, the path is set to `~/Documents/ida scripts`.

## Requirements
- IDA Pro (tested with version 7.0 or later).
- Python with the GitPython library installed (`pip install GitPython`).

## License
This project is licensed under the MIT License. For more details, see the LICENSE file.

## Support
If you encounter any issues or have questions, please open an issue in this repository.
