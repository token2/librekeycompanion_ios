# Links this package into the Libre Key Companion iOS app target as a local
# Swift package. Run from the app repo root on the App Store branch:
#   ruby ../Token2USBFido/scripts/link-into-app.rb [relative/path/to/Token2USBFido]
# Idempotent. Commit the resulting project.pbxproj change on the private
# App Store branch only — never on the public main branch.
require 'xcodeproj'
rel = ARGV[0] || '../Token2USBFido'
proj = Xcodeproj::Project.open('LibreKeyCompanion.xcodeproj')
target = proj.targets.find { |t| t.name == 'LibreKeyCompanion' } or abort 'app target not found'

pkg = proj.root_object.package_references.find { |r| r.respond_to?(:relative_path) && r.relative_path == rel }
unless pkg
  pkg = proj.new(Xcodeproj::Project::Object::XCLocalSwiftPackageReference)
  pkg.relative_path = rel
  proj.root_object.package_references << pkg
end

unless target.package_product_dependencies.any? { |d| d.product_name == 'Token2USBFido' }
  dep = proj.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
  dep.product_name = 'Token2USBFido'
  dep.package = pkg
  target.package_product_dependencies << dep
  bf = proj.new(Xcodeproj::Project::Object::PBXBuildFile)
  bf.product_ref = dep
  target.frameworks_build_phase.files << bf
end
proj.save
puts "Linked Token2USBFido (#{rel}) into #{target.name}"
