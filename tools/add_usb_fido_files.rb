# Adds the USB FIDO channel files to the app target. Idempotent.
# Usage: ruby tools/add_usb_fido_files.rb
require 'xcodeproj'
proj = Xcodeproj::Project.open('LibreKeyCompanion.xcodeproj')
target = proj.targets.find { |t| t.name == 'LibreKeyCompanion' } or abort 'app target not found'
files = {
  'LibreKeyCompanion/FIDO/CTAP' => %w[CtapChannel.swift Token2UsbFidoProvider.swift],
  'LibreKeyCompanion/UI/FIDO'   => %w[FingerprintManagerView.swift],
  'LibreKeyCompanion/UI/Shared' => %w[PinTextField.swift],
  'LibreKeyCompanion/UI/Info'   => %w[ChannelsView.swift],
}
def group_for(proj, path)
  path.split('/').inject(proj.main_group) do |g, comp|
    g.children.find { |c| c.isa == 'PBXGroup' && (c.path == comp || c.name == comp) } or abort "group #{comp} not found in #{path}"
  end
end
files.each do |dir, names|
  g = group_for(proj, dir)
  names.each do |n|
    next if g.files.any? { |f| f.path == n }
    ref = g.new_reference(n)
    target.source_build_phase.add_file_reference(ref)
    puts "added #{dir}/#{n}"
  end
end
proj.save
