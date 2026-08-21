/**
 * Dependency-free public build-profile descriptor shared by generation and runtime.
 * A profile or URI-version change must flow through this single source of truth.
 */
export const BASE_PRODUCT_PROFILE = "PERSONAL_DIRECT_OWNER" as const;
export const RESOURCE_URI_VERSION = "v1" as const;
export const SUPPORTED_PRODUCT_PROFILES = [BASE_PRODUCT_PROFILE] as const;

export const BASE_BUILD_PROFILE_CONTRACT = Object.freeze({
  productProfile: BASE_PRODUCT_PROFILE,
  supportedProfiles: SUPPORTED_PRODUCT_PROFILES,
  resourceUriVersion: RESOURCE_URI_VERSION,
});
