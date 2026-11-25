# Development preview release checklist

- Run the unit suite and validate the desktop entry.
- Confirm real CLI inventory and local update-candidate review.
- Run Debian and Ubuntu integration jobs and GUI smoke tests before tagging a stable release.
- Confirm installation in a clean virtual environment.
- Publish the scanner and companion schema repositories independently.
- Keep the synthetic database fixture explicitly labeled; no operational vendor snapshot is supplied in this preview.
- Review vendor feed terms and coverage before distributing real snapshot data.
- Publish release archive checksums through a trusted GitHub release channel.

This preview is not a complete vulnerability assessment tool and does not install updates.
