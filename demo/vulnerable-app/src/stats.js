const _ = require('lodash');

function summarize(orders) {
  return _.mapValues(_.groupBy(orders, 'customer'), (items) => ({
    count: items.length,
    total: _.sumBy(items, 'amount'),
  }));
}

function topCustomers(orders, limit = 3) {
  const rows = _.map(summarize(orders), (value, customer) => ({ customer, ...value }));
  return _.take(_.orderBy(rows, ['total', 'customer'], ['desc', 'asc']), limit);
}

function lookup(source, path, fallback = null) {
  return _.get(source, path, fallback);
}

module.exports = { summarize, topCustomers, lookup };
