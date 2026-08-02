/**
 * @omniai/types — shared TypeScript contracts between frontend and backend.
 *
 * These mirror the Pydantic schemas in apps/api. When the API stabilizes,
 * this package will be generated from the OpenAPI spec (see docs/API_GUIDELINES.md)
 * instead of hand-written.
 */

/** Standard API error envelope — see docs/API_GUIDELINES.md */
export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    request_id: string;
  };
}
