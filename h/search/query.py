# -*- coding: utf-8 -*-

from h import storage
from h.util import uri

LIMIT_DEFAULT = 20
LIMIT_MAX = 200

branches = [False]*34

class Builder(object):

    """
    Build a query for execution in Elasticsearch.
    """

    def __init__(self):
        self.filters = []
        self.matchers = []
        self.aggregations = []

    def append_filter(self, f):
        branches[0] = True
        self.filters.append(f)

    def append_matcher(self, m):
        branches[1] = True
        self.matchers.append(m)

    def append_aggregation(self, a):
        branches[2] = True
        self.aggregations.append(a)

    def build(self, params):
        """Get the resulting query object from this query builder."""
        branches[3] = True
        params = params.copy()

        p_from = extract_offset(params)
        p_size = extract_limit(params)
        p_sort = extract_sort(params)

        filters = [f(params) for f in self.filters]
        matchers = [m(params) for m in self.matchers]
        aggregations = {a.key: a(params) for a in self.aggregations}
        filters = [f for f in filters if f is not None]
        matchers = [m for m in matchers if m is not None]

        # Remaining parameters are added as straightforward key-value matchers
        for key, value in params.items():
            branches[4] = True
            matchers.append({"match": {key: value}})

        query = {"match_all": {}}

        if matchers:
            branches[5] = True
            query = {"bool": {"must": matchers}}

        if filters:
            branches[6] = True
            query = {
                "filtered": {
                    "filter": {"and": filters},
                    "query": query,
                }
            }

        return {
            "from": p_from,
            "size": p_size,
            "sort": p_sort,
            "query": query,
            "aggs": aggregations,
        }


def extract_offset(params):
    branches[7] = True
    try:
        val = int(params.pop("offset"))
        if val < 0:
            raise ValueError
    except (ValueError, KeyError):
        return 0
    else:
        return val


def extract_limit(params):
    branches[8] = True
    try:
        val = int(params.pop("limit"))
        val = min(val, LIMIT_MAX)
        if val < 0:
            raise ValueError
    except (ValueError, KeyError):
        return LIMIT_DEFAULT
    else:
        return val


def extract_sort(params):
    branches[9] = True
    return [{
        params.pop("sort", "updated"): {
            "ignore_unmapped": True,
            "order": params.pop("order", "desc"),
        }
    }]


class TopLevelAnnotationsFilter(object):

    """Matches top-level annotations only, filters out replies."""

    def __call__(self, _):
        branches[10] = True
        return {'missing': {'field': 'references'}}


class AuthorityFilter(object):

    """
    Match only annotations created by users belonging to a specific authority.
    """

    def __init__(self, authority):
        self.authority = authority

    def __call__(self, params):
        branches[11] = True
        return {'term': {'authority': self.authority}}


class AuthFilter(object):

    """
    A filter that selects only annotations the user is authorised to see.

    Only annotations that are shared, or private annotations made
    by the logged-in user will pass through this filter.
    """

    def __init__(self, request):
        """
        Initialize a new AuthFilter.

        :param request: the pyramid.request object
        """
        self.request = request

    def __call__(self, params):
        branches[12] = True
        public_filter = {'term': {'shared': True}}

        userid = self.request.authenticated_userid
        if userid is None:
            branches[13] = True
            return public_filter

        return {'or': [
            public_filter,
            {'term': {'user_raw': userid}},
        ]}


class GroupFilter(object):

    """
    Matches only those annotations belonging to the specified group.
    """

    def __call__(self, params):
        # Remove parameter if passed, preventing fall-through to default query
        group = params.pop("group", None)
        branches[14] = True

        if group is not None:
            branches[15] = True
            return {"term": {"group": group}}


class UriFilter(object):

    """
    A filter that selects only annotations where the 'uri' parameter matches.
    """

    def __init__(self, request):
        """Initialize a new UriFilter.

        :param request: the pyramid.request object

        """
        self.request = request

    def __call__(self, params):
        branches[16] = True
        if 'uri' not in params and 'url' not in params:
            branches[17] = True
            return None
        query_uris = [v for k, v in params.items() if k in ['uri', 'url']]
        if 'uri' in params:
            branches[18] = True
            del params['uri']
        if 'url' in params:
            branches[19] = True
            del params['url']

        uris = set()
        for query_uri in query_uris:
            branches[20] = True
            expanded = storage.expand_uri(self.request.db, query_uri)

            us = [uri.normalize(u) for u in expanded]
            uris.update(us)

        return {"terms": {"target.scope": list(uris)}}


class UserFilter(object):

    """
    A filter that selects only annotations where the 'user' parameter matches.
    """

    def __call__(self, params):
        branches[21] = True
        if 'user' not in params:
            branches[22] = True
            return None

        users = [v.lower() for k, v in params.items() if k == 'user']
        del params['user']

        return {'terms': {'user': users}}


class DeletedFilter(object):

    """
    A filter that only returns non-deleted documents.

    Documents are not getting deleted from the index, they only get marked as
    deleted.
    """

    def __call__(self, _):
        branches[23] = True
        return {"bool": {"must_not": {"exists": {"field": "deleted"}}}}


class AnyMatcher(object):

    """
    Matches the contents of a selection of fields against the `any` parameter.
    """

    def __call__(self, params):
        branches[24] = True
        if "any" not in params:
            branches[25] = True
            return None
        qs = ' '.join([v for k, v in params.items() if k == "any"])
        result = {
            "simple_query_string": {
                "fields": ["quote", "tags", "text", "uri.parts"],
                "query": qs,
            }
        }
        del params["any"]
        return result


class TagsMatcher(object):

    """Matches the tags field against 'tag' or 'tags' parameters."""

    def __call__(self, params):
        branches[26] = True
        tags = set(v for k, v in params.items() if k in ['tag', 'tags'])
        try:
            del params['tag']
            del params['tags']
        except KeyError:
            pass
        matchers = [{'match': {'tags': {'query': t, 'operator': 'and'}}}
                    for t in tags]
        return {'bool': {'must': matchers}} if matchers else None


class RepliesMatcher(object):

    """Matches any replies to any of the given annotation ids."""

    def __init__(self, ids):
        self.annotation_ids = ids

    def __call__(self, _):
        branches[27] = True
        return {
            'terms': {'references': self.annotation_ids}
        }


class TagsAggregation(object):
    def __init__(self, limit=0):
        self.key = 'tags'
        self.limit = limit

    def __call__(self, _):
        branches[28] = True
        return {
            "terms": {
                "field": "tags_raw",
                "size": self.limit
            }
        }

    def parse_result(self, result):
        branches[29] = True
        if not result:
            branches[30] = True
            return {}

        return [
            {'tag': b['key'], 'count': b['doc_count']}
            for b in result['buckets']
        ]


class UsersAggregation(object):
    def __init__(self, limit=0):
        self.key = 'users'
        self.limit = limit

    def __call__(self, _):
        branches[31] = True
        return {
            "terms": {
                "field": "user_raw",
                "size": self.limit
            }
        }

    def parse_result(self, result):
        branches[32] = True
        if not result:
            branches[33] = True
            return {}

        return [
            {'user': b['key'], 'count': b['doc_count']}
            for b in result['buckets']
        ]
