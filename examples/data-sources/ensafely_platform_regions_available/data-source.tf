data "ensafely_platform_regions_available" "all" {}

output "selectable_regions" {
  value = data.ensafely_platform_regions_available.all.names
}

output "region_limit" {
  # -1 is unlimited.
  value = data.ensafely_platform_regions_available.all.limit
}
